#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "bsp/device.h"
#include "bsp/display.h"
#include "bsp/input.h"
#include "bsp/led.h"
#include "bsp/power.h"
#include "bsp/rtc.h"
#include "bsp/tanmatsu.h"
#include "crypto/aes.h"
#include "crypto/hmac_sha256.h"
#include "custom_certificates.h"
#include "device_settings.h"
#include "driver/gpio.h"
#include "ed25519/ed_25519.h"
#include "esp_hosted_custom.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_types.h"
#include "esp_log.h"
#include "hal/lcd_types.h"
#include "lora.h"
#include "lora_settings_handler.h"
#include "meshcore/packet.h"
#include "meshcore/payload/advert.h"
#include "meshcore/payload/grp_txt.h"
#include "nvs_flash.h"
#include "pax_fonts.h"
#include "pax_gfx.h"
#include "pax_text.h"
#include "portmacro.h"
#include "wifi_connection.h"
#include "wifi_remote.h"

#define BLACK 0xFF000000
#define WHITE 0xFFFFFFFF
#define RED   0xFFFF0000

#define CHAT_MESSAGE_NAME_SIZE 40
#define CHAT_MESSAGE_TEXT_SIZE 200

typedef struct {
    uint8_t  channel_hash;
    char     name[CHAT_MESSAGE_NAME_SIZE];  // sender name (UTF-8)
    char     text[CHAT_MESSAGE_TEXT_SIZE];  // Message text (UTF-8)
    uint32_t received_at;                   // Unix timestamp (local clock)
    uint32_t timestamp;                     // Unix timestamp (remote clock)
    bool     sent;                          // Sent by us
    bool     repeated;                      // Repeated by others
} chat_message_t;

// Constants
static char const TAG[] = "main";

// Global variables
static size_t                       display_h_res        = 0;
static size_t                       display_v_res        = 0;
static lcd_color_rgb_pixel_format_t display_color_format = LCD_COLOR_PIXEL_FORMAT_RGB565;
static lcd_rgb_data_endian_t        display_data_endian  = LCD_RGB_DATA_ENDIAN_LITTLE;
static pax_buf_t                    fb                   = {0};
static QueueHandle_t                input_event_queue    = NULL;
static chat_message_t               chat_messages[16]    = {0};
static size_t                       chat_message_index   = 0;
static size_t                       text_buffer_length   = 0;
static char                         text_buffer[200]     = {0};

const char* type_to_string(meshcore_payload_type_t type) {
    switch (type) {
        case MESHCORE_PAYLOAD_TYPE_REQ:
            return "Request";
        case MESHCORE_PAYLOAD_TYPE_RESPONSE:
            return "Response";
        case MESHCORE_PAYLOAD_TYPE_TXT_MSG:
            return "Plain text message";
        case MESHCORE_PAYLOAD_TYPE_ACK:
            return "Acknowledgement";
        case MESHCORE_PAYLOAD_TYPE_ADVERT:
            return "Node advertisement";
        case MESHCORE_PAYLOAD_TYPE_GRP_TXT:
            return "Group text message (unverified)";
        case MESHCORE_PAYLOAD_TYPE_GRP_DATA:
            return "Group data message (unverified)";
        case MESHCORE_PAYLOAD_TYPE_ANON_REQ:
            return "Anonymous request";
        case MESHCORE_PAYLOAD_TYPE_PATH:
            return "Returned path";
        case MESHCORE_PAYLOAD_TYPE_TRACE:
            return "Trace";
        case MESHCORE_PAYLOAD_TYPE_MULTIPART:
            return "Multipart";
        case MESHCORE_PAYLOAD_TYPE_RAW_CUSTOM:
            return "Custom raw";
        default:
            return "UNKNOWN";
    }
}

const char* route_to_string(meshcore_route_type_t route) {
    switch (route) {
        case MESHCORE_ROUTE_TYPE_TRANSPORT_FLOOD:
            return "Transport flood";
        case MESHCORE_ROUTE_TYPE_FLOOD:
            return "Flood";
        case MESHCORE_ROUTE_TYPE_DIRECT:
            return "Direct";
        case MESHCORE_ROUTE_TYPE_TRANSPORT_DIRECT:
            return "Transport direct";
        default:
            return "Unknown";
    }
}

const char* role_to_string(meshcore_device_role_t role) {
    switch (role) {
        case MESHCORE_DEVICE_ROLE_CHAT_NODE:
            return "Chat Node";
        case MESHCORE_DEVICE_ROLE_REPEATER:
            return "Repeater";
        case MESHCORE_DEVICE_ROLE_ROOM_SERVER:
            return "Room Server";
        case MESHCORE_DEVICE_ROLE_SENSOR:
            return "Sensor";
        default:
            return "Unknown";
    }
}

static uint8_t mc_keys[2][16] = {
    {0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72},  // public
    {0x9c, 0xd8, 0xfc, 0xf2, 0x2a, 0x47, 0x33, 0x3b, 0x59, 0x1d, 0x96, 0xa2, 0xb8, 0x48, 0xb7, 0x3f},  // test
};

static uint8_t verification_data[MESHCORE_MAX_PAYLOAD_SIZE] = {0};

static void radio_callback(uint8_t type, uint8_t* payload, uint16_t payload_length) {
    if (type == 1) {
        lora_transaction_receive(payload, payload_length);
    } else {
        ESP_LOGI(TAG, "Received message from radio: type: %d, payload length: %d", type, payload_length);
        for (int i = 0; i < payload_length; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\r\n");
    }
}

static void blit(void) {
    bsp_display_blit(0, 0, display_h_res, display_v_res, pax_buf_get_pixels(&fb));
}

static void blink_message_led(bool r, bool g, bool b) {
    tanmatsu_coprocessor_handle_t handle;
    bsp_tanmatsu_coprocessor_get_handle(&handle);
    tanmatsu_coprocessor_set_message(handle, r, g, b, true, false, false, false, false);
    vTaskDelay(pdMS_TO_TICKS(500));
    tanmatsu_coprocessor_set_message(handle, false, false, false, false, false, false, false, false);
}

bool handle_chat_message(uint8_t channel_hash, const char* name, const char* text, uint32_t timestamp, bool sent) {
    printf("Chat message received - Name: '%s', Text: '%s', Timestamp: %" PRIu32 "\n", name, text, timestamp);
    size_t amount_of_messages = sizeof(chat_messages) / sizeof(chat_message_t);

    chat_message_t* previous_message = &chat_messages[(chat_message_index - 1) % amount_of_messages];

    if (previous_message->channel_hash == channel_hash && strcmp(previous_message->name, name) == 0 &&
        strcmp(previous_message->text, text) == 0) {
        previous_message->repeated = true;
        // Bit of a hack but oh well, this is just a preview app anyway
        bsp_input_event_t event    = {.type = INPUT_EVENT_TYPE_LAST};
        bsp_input_inject_event(&event);
        return false;
    }

    chat_message_t* message = &chat_messages[chat_message_index];

    message->channel_hash = channel_hash;
    snprintf(message->name, CHAT_MESSAGE_NAME_SIZE, "%s", name);
    snprintf(message->text, CHAT_MESSAGE_TEXT_SIZE, "%s", text);
    message->timestamp = timestamp;
    message->sent      = sent;

    chat_message_index++;
    if (chat_message_index >= amount_of_messages) {
        chat_message_index = 0;
    }

    // Bit of a hack but oh well, this is just a preview app anyway
    bsp_input_event_t event = {.type = INPUT_EVENT_TYPE_LAST};
    bsp_input_inject_event(&event);

    return true;
}

void meshcore_parse(lora_protocol_lora_packet_t* packet) {
    meshcore_message_t message;
    if (meshcore_deserialize(packet->data, packet->length, &message) < 0) {
        ESP_LOGE(TAG, "Failed to deserialize message");
        return;
    }

    printf("Type: %s [%d]\n", type_to_string(message.type), message.type);
    printf("Route: %s [%d]\n", route_to_string(message.route), message.route);
    printf("Version: %d\n", message.version);
    printf("Path Length: %d\n", message.path_length);
    if (message.path_length > 0) {
        printf("Path: ");
        for (unsigned int i = 0; i < message.path_length; i++) {
            printf("0x%02x, ", message.path[i]);
        }
        printf("\n");
    }
    printf("Payload Length: %d\n", message.payload_length);
    if (message.payload_length > 0) {
        printf("Payload [%d]: ", message.payload_length);
        for (unsigned int i = 0; i < message.payload_length; i++) {
            printf("%02X", message.payload[i]);
        }
        printf("\n");
    }

    if (message.type == MESHCORE_PAYLOAD_TYPE_ADVERT) {
        meshcore_advert_t advert;
        if (meshcore_advert_deserialize(message.payload, message.payload_length, &advert) >= 0) {
            printf("Decoded node advertisement:\n");
            printf("Public Key: ");
            for (unsigned int i = 0; i < MESHCORE_PUB_KEY_SIZE; i++) {
                printf("%02X", advert.pub_key[i]);
            }
            printf("\n");
            printf("Timestamp: %" PRIu32 "\n", advert.timestamp);
            printf("Signature: ");
            for (unsigned int i = 0; i < MESHCORE_SIGNATURE_SIZE; i++) {
                printf("%02X", advert.signature[i]);
            }
            printf("\n");
            printf("Role: %s\n", role_to_string(advert.role));
            if (advert.position_valid) {
                printf("Position: lat=%" PRIi32 ", lon=%" PRIi32 "\n", advert.position_lat, advert.position_lon);
            } else {
                printf("Position: (not available)\n");
            }
            if (advert.extra1_valid) {
                printf("Extra1: %u\n", advert.extra1);
            } else {
                printf("Extra1: (not available)\n");
            }
            if (advert.extra2_valid) {
                printf("Extra2: %u\n", advert.extra2);
            } else {
                printf("Extra2: (not available)\n");
            }
            if (advert.name_valid) {
                printf("Name: %s\n", advert.name);
            } else {
                printf("Name: (not available)\n");
            }

            memset(verification_data, 0, sizeof(verification_data));
            size_t verification_data_size = 0;
            memcpy(&verification_data[verification_data_size], advert.pub_key, MESHCORE_PUB_KEY_SIZE);
            verification_data_size += MESHCORE_PUB_KEY_SIZE;
            memcpy(&verification_data[verification_data_size], &advert.timestamp, sizeof(uint32_t));
            verification_data_size += sizeof(uint32_t);
            memcpy(&verification_data[verification_data_size],
                   &message.payload[MESHCORE_PUB_KEY_SIZE + sizeof(uint32_t) + MESHCORE_SIGNATURE_SIZE],
                   message.payload_length - MESHCORE_PUB_KEY_SIZE - sizeof(uint32_t) - MESHCORE_SIGNATURE_SIZE);
            verification_data_size +=
                message.payload_length - MESHCORE_PUB_KEY_SIZE - sizeof(uint32_t) - MESHCORE_SIGNATURE_SIZE;

            printf("Key for signature verification: ");
            for (size_t i = 0; i < MESHCORE_PUB_KEY_SIZE; i++) {
                printf("%02X", advert.pub_key[i]);
            }
            printf("\r\n");

            printf("Signature: ");
            for (size_t i = 0; i < MESHCORE_SIGNATURE_SIZE; i++) {
                printf("%02X", advert.signature[i]);
            }
            printf("\r\n");

            printf("Data for signature verification: ");
            for (size_t i = 0; i < verification_data_size; i++) {
                printf("%02X", verification_data[i]);
            }
            printf("\r\n");

            if (ed25519_verify(advert.signature, verification_data, verification_data_size, advert.pub_key)) {
                printf("Advertisement signature verification SUCCESSFUL.\n");
                blink_message_led(false, false, true);
            } else {
                printf("Warning: Advertisement signature verification FAILED!\n");
            }
        } else {
            printf("Failed to decode node advertisement payload.\n");
        }
    } else if (message.type == MESHCORE_PAYLOAD_TYPE_GRP_TXT) {
        meshcore_grp_txt_t grp_txt;
        if (meshcore_grp_txt_deserialize(message.payload, message.payload_length, &grp_txt) >= 0) {
            printf("Decoded group text message:\n");
            printf("Channel Hash: %02X\n", grp_txt.channel_hash);
            printf("Data Length: %d\n", grp_txt.data_length);
            printf("Received MAC:");

            for (unsigned int i = 0; i < MESHCORE_CIPHER_MAC_SIZE; i++) {
                printf("%02X", grp_txt.mac[i]);
            }
            printf("\n");

            printf("Data [%d]: ", grp_txt.data_length);
            for (unsigned int i = 0; i < grp_txt.data_length; i++) {
                printf("%02X", grp_txt.data[i]);
            }
            printf("\n");

            // TO-DO: all of this MAC verification and decryption should be moved somewhere else

            for (uint8_t i = 0; i < 1; i++) {
                uint8_t* key = mc_keys[i];

                uint8_t out[128];
                size_t out_len = hmac_sha256(key, 16, grp_txt.data, grp_txt.data_length, out, MESHCORE_CIPHER_MAC_SIZE);

                printf("Calculated MAC [%d]: ", out_len);
                for (unsigned int i = 0; i < out_len; i++) {
                    printf("%02X", out[i]);
                }
                printf("\n");

                if (memcmp(out, grp_txt.mac, MESHCORE_CIPHER_MAC_SIZE) == 0) {
                    printf("MAC verification: SUCCESS\n");

                    // Decrypt data (in-place)
                    struct AES_ctx ctx;
                    AES_init_ctx(&ctx, key);
                    for (uint8_t i = 0; i < (grp_txt.data_length / 16); i++) {
                        AES_ECB_decrypt(&ctx, &grp_txt.data[i * 16]);
                    }

                    meshcore_grp_txt_data_t data = {0};
                    meshcore_grp_txt_data_deserialize(grp_txt.data, grp_txt.data_length, &data);

                    printf("Timestamp: %" PRIu32 "\n", data.timestamp);
                    printf("Text Type: %u\n", data.text_type);
                    printf("Message: '%s'\n", data.text);

                    char*  ptr      = data.text;
                    char*  text_ptr = data.text;
                    size_t len      = strlen(ptr);

                    for (size_t i = 0; i < len; i++) {
                        ptr = &data.text[i];
                        if (*ptr == ':') {
                            *ptr = '\0';
                            if (i + 2 < len) {
                                text_ptr = ptr + 2;
                            }
                            break;
                        }
                    }

                    bool handled =
                        handle_chat_message(grp_txt.channel_hash, data.text, text_ptr, data.timestamp, false);

                    blink_message_led(!handled, handled, false);
                    break;
                } else {
                    printf("MAC verification: FAILURE (key %u)\n", i);
                }
            }
        } else {
            printf("Failed to decode group text message payload.\n");
        }
    }
}

static void meshcore_task(void* pvParameters) {
    while (1) {
        lora_protocol_lora_packet_t packet = {0};
        if (lora_receive_packet(&packet, portMAX_DELAY) == ESP_OK) {
            meshcore_parse(&packet);
        }
    }
    vTaskDelete(NULL);
}

void render_chat(void) {
    pax_simple_rect(&fb, BLACK, 0, 64, pax_buf_get_width(&fb), pax_buf_get_height(&fb) - 128);
    size_t amount_of_messages = sizeof(chat_messages) / sizeof(chat_message_t);
    for (size_t i = 0; i < amount_of_messages; i++) {
        chat_message_t* message = &chat_messages[(chat_message_index + i) % amount_of_messages];
        if (message->timestamp != 0) {
            char text[CHAT_MESSAGE_NAME_SIZE + CHAT_MESSAGE_TEXT_SIZE + 4];
            snprintf(text, sizeof(text), "%s: %s", message->name, message->text);
            pax_draw_text(&fb, (message->repeated && message->sent) ? 0xFF00FF00 : (message->sent ? 0xFFFFFF00 : WHITE),
                          pax_font_saira_regular, 16, 0, 72 + (i * 20), text);
        }
    }
    blit();
}

void handle_input(char input) {
    if (input == '\0') {
        // Clear input (used after sending a message)
        text_buffer_length = 0;
        text_buffer[0]     = '\0';
    } else if (input == '\b') {
        if (text_buffer_length > 0) {
            text_buffer_length--;
            text_buffer[text_buffer_length] = '\0';
        }
    } else if (text_buffer_length < sizeof(text_buffer) - 1) {
        text_buffer[text_buffer_length] = input;
        text_buffer_length++;
        text_buffer[text_buffer_length] = '\0';
    }

    pax_simple_rect(&fb, BLACK, 0, pax_buf_get_height(&fb) - 64, pax_buf_get_width(&fb), 64);
    pax_draw_text(&fb, 0xFFFFFF00, pax_font_saira_regular, 16, 0, pax_buf_get_height(&fb) - 64 + 16, text_buffer);
    blit();
}

void send_input(void) {
    if (strlen(text_buffer) == 0) {
        return;
    }
    printf("Sending message: '%s'\n", text_buffer);

    char nickname[CHAT_MESSAGE_NAME_SIZE] = {0};
    device_settings_get_owner_nickname(nickname, sizeof(nickname));

    char message_text[256] = {0};
    snprintf(message_text, sizeof(message_text), "%s: %s", nickname, text_buffer);
    meshcore_grp_txt_t grp_txt = {0};
    grp_txt.channel_hash       = 0x11;  // #public

    // Data to be encrypted
    meshcore_grp_txt_data_t data = {0};
    data.timestamp               = (uint32_t)time(NULL);
    data.text_type               = 0x00;  // plain text
    memcpy(data.text, message_text, strlen(message_text));

    // Add message to chatlog
    handle_chat_message(grp_txt.channel_hash, nickname, text_buffer, data.timestamp, true);

    // Pack data
    meshcore_grp_txt_data_serialize(&data, grp_txt.data, &grp_txt.data_length);

    // Encrypt data
    uint8_t encrypt_length = grp_txt.data_length;
    while (encrypt_length % 16 != 0) {
        encrypt_length++;
    }
    for (uint8_t i = grp_txt.data_length; i < encrypt_length; i++) {
        grp_txt.data[i] = 0;
    }
    printf("Data length = %u, encrypt length = %u\n", grp_txt.data_length, encrypt_length);

    uint8_t*       key = mc_keys[0];  // #public
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    for (uint8_t i = 0; i < (encrypt_length / 16); i++) {
        AES_ECB_encrypt(&ctx, &grp_txt.data[i * 16]);
    }

    printf("Encrypted data [%d]: ", encrypt_length);
    for (size_t i = 0; i < encrypt_length; i++) {
        printf("%02X", grp_txt.data[i]);
    }
    printf("\n");
    grp_txt.data_length = encrypt_length;

    // Calculate MAC
    size_t size = hmac_sha256(key, 16, grp_txt.data, grp_txt.data_length, grp_txt.mac, MESHCORE_CIPHER_MAC_SIZE);
    printf("Calculated MAC [%d]: ", size);
    for (unsigned int i = 0; i < size; i++) {
        printf("%02X", grp_txt.mac[i]);
    }
    printf("\n");

    // Assemble message
    meshcore_message_t message = {0};
    message.type               = MESHCORE_PAYLOAD_TYPE_GRP_TXT;
    message.route              = MESHCORE_ROUTE_TYPE_FLOOD;
    message.version            = 0x00;
    meshcore_grp_txt_serialize(&grp_txt, message.payload, &message.payload_length);

    lora_protocol_lora_packet_t packet = {0};
    int                         result = meshcore_serialize(&message, packet.data, &packet.length);

    if (result >= 0) {
        ESP_LOGI(TAG, "Message serialized successfully, length: %d", packet.length);
    } else {
        ESP_LOGE(TAG, "Failed to serialize message");
        return;
    }
    lora_send_packet(&packet);
    handle_input('\0');
}

void app_main(void) {
    // Start the GPIO interrupt service
    gpio_install_isr_service(0);

    // Initialize the Non Volatile Storage partition
    esp_err_t res = nvs_flash_init();
    if (res == ESP_ERR_NVS_NO_FREE_PAGES || res == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        res = nvs_flash_erase();
        if (res != ESP_OK) {
            ESP_LOGE(TAG, "Failed to erase NVS flash: %d", res);
            return;
        }
        res = nvs_flash_init();
    }
    if (res != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize NVS flash: %d", res);
        return;
    }

    // Initialize the Board Support Package
    const bsp_configuration_t bsp_configuration = {
        .display =
            {
                .requested_color_format = LCD_COLOR_PIXEL_FORMAT_RGB888,
                .num_fbs                = 1,
            },
    };
    res = bsp_device_initialize(&bsp_configuration);
    if (res != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize BSP: %d", res);
        return;
    }

    // Get display parameters and rotation
    res = bsp_display_get_parameters(&display_h_res, &display_v_res, &display_color_format, &display_data_endian);
    if (res != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get display parameters: %d", res);
        return;
    }

    // Convert ESP-IDF color format into PAX buffer type
    pax_buf_type_t format = PAX_BUF_24_888RGB;
    switch (display_color_format) {
        case LCD_COLOR_PIXEL_FORMAT_RGB565:
            format = PAX_BUF_16_565RGB;
            break;
        case LCD_COLOR_PIXEL_FORMAT_RGB888:
            format = PAX_BUF_24_888RGB;
            break;
        default:
            break;
    }

    // Convert BSP display rotation format into PAX orientation type
    bsp_display_rotation_t display_rotation = bsp_display_get_default_rotation();
    pax_orientation_t      orientation      = PAX_O_UPRIGHT;
    switch (display_rotation) {
        case BSP_DISPLAY_ROTATION_90:
            orientation = PAX_O_ROT_CCW;
            break;
        case BSP_DISPLAY_ROTATION_180:
            orientation = PAX_O_ROT_HALF;
            break;
        case BSP_DISPLAY_ROTATION_270:
            orientation = PAX_O_ROT_CW;
            break;
        case BSP_DISPLAY_ROTATION_0:
        default:
            orientation = PAX_O_UPRIGHT;
            break;
    }

    // Initialize graphics stack
    pax_buf_init(&fb, NULL, display_h_res, display_v_res, format);
    pax_buf_reversed(&fb, display_data_endian == LCD_RGB_DATA_ENDIAN_BIG);
    pax_buf_set_orientation(&fb, orientation);

    // Get input event queue from BSP
    ESP_ERROR_CHECK(bsp_input_get_queue(&input_event_queue));

    // LEDs
    bsp_led_set_pixel(4, 0x000000);
    bsp_led_set_pixel(5, 0x000000);
    bsp_led_send();
    bsp_led_set_mode(true);

    // Clock
    bsp_rtc_update_time();

    // Start WiFi stack (if your app does not require WiFi or BLE you can remove this section)
    pax_background(&fb, BLACK);
    pax_draw_text(&fb, WHITE, pax_font_sky_mono, 16, 0, 0, "Connecting to radio...");
    blit();

    esp_hosted_set_custom_callback(radio_callback);

    if (wifi_remote_initialize() == ESP_OK) {

        pax_background(&fb, BLACK);
        pax_draw_text(&fb, WHITE, pax_font_sky_mono, 16, 0, 0, "Starting WiFi stack...");
        blit();
        wifi_connection_init_stack();  // Start the Espressif WiFi stack

        res = lora_init(16);
        if (res != ESP_OK) {
            pax_background(&fb, RED);
            pax_draw_text(&fb, WHITE, pax_font_sky_mono, 16, 0, 0, "Failed to connect to WiFi network");
            blit();
            return;
        }

    } else {
        bsp_power_set_radio_state(BSP_POWER_RADIO_STATE_OFF);
        ESP_LOGE(TAG, "Radio not responding");
        pax_background(&fb, RED);
        pax_draw_text(&fb, WHITE, pax_font_sky_mono, 16, 0, 0, "Radio not responding");
        blit();
        return;
    }

    lora_protocol_status_params_t status;
    res = lora_get_status(&status);
    if (res != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read LoRa radio status: %s", esp_err_to_name(res));
        vTaskDelete(NULL);
    }

    ESP_LOGI(TAG, "LoRa radio version string: %s", status.version_string);

    lora_protocol_mode_t mode;
    res = lora_get_mode(&mode);
    if (res != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get LoRa mode: %s", esp_err_to_name(res));
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "LoRa mode: %d", (int)mode);

    if (status.chip_type == LORA_PROTOCOL_CHIP_SX1268) {
        ESP_LOGW(TAG, "SX1268 LoRa radio detected");
    } else {
        ESP_LOGW(TAG, "SX1262 LoRa radio detected");
    }

    res = lora_set_mode(LORA_PROTOCOL_MODE_STANDBY_RC);
    if (res == ESP_OK) {
        ESP_LOGI(TAG, "LoRa set to standby mode");
    } else {
        ESP_LOGE(TAG, "Failed to set LoRa mode: %s", esp_err_to_name(res));
    }

    res = lora_apply_settings();
    if (res == ESP_OK) {
        ESP_LOGI(TAG, "LoRa configuration set");
    } else {
        ESP_LOGE(TAG, "Failed to set LoRa configuration: %s", esp_err_to_name(res));
    }

    res = lora_set_mode(LORA_PROTOCOL_MODE_RX);
    if (res == ESP_OK) {
        ESP_LOGI(TAG, "LoRa set to RX mode");
    } else {
        ESP_LOGE(TAG, "Failed to set LoRa mode: %s", esp_err_to_name(res));
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    res = lora_get_mode(&mode);
    if (res == ESP_OK) {
        ESP_LOGI(TAG, "LoRa mode (after setting to RX): %d", (int)mode);
    } else {
        ESP_LOGE(TAG, "Failed to get LoRa mode: %s", esp_err_to_name(res));
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    // Main section of the app

    // This example shows how to read from the BSP event queue to read input events

    // If you want to run something at an interval in this same main thread you can replace portMAX_DELAY with an
    // amount of ticks to wait, for example pdMS_TO_TICKS(1000)

    xTaskCreatePinnedToCore(meshcore_task, TAG, 1024 * 16, NULL, 10, NULL, CONFIG_SOC_CPU_CORES_NUM - 1);

    pax_background(&fb, BLACK);
    pax_draw_text(&fb, 0xFFFF00FF, pax_font_saira_regular, 24, 0, 0, "Meshcore chat app (preview) - build 2");
    blit();

    while (1) {
        bsp_input_event_t event;
        if (xQueueReceive(input_event_queue, &event, portMAX_DELAY) == pdTRUE) {
            switch (event.type) {
                case INPUT_EVENT_TYPE_LAST:
                    // new chat message
                    render_chat();
                    break;
                case INPUT_EVENT_TYPE_KEYBOARD: {
                    handle_input(event.args_keyboard.ascii);
                    break;
                }
                case INPUT_EVENT_TYPE_NAVIGATION: {
                    if (event.args_navigation.state) {
                        if (event.args_navigation.key == BSP_INPUT_NAVIGATION_KEY_RETURN) {
                            send_input();
                            render_chat();
                        }
                        break;
                    }
                    case INPUT_EVENT_TYPE_ACTION: {
                        break;
                    }
                    case INPUT_EVENT_TYPE_SCANCODE: {
                        break;
                    }
                    default:
                        break;
                }
            }
        }
    }
}