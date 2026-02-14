idf_build_get_property(idf_target IDF_TARGET)
if("${idf_target}" STREQUAL "esp32p4")
list(APPEND extra_requires esp-hosted-tanmatsu)
endif()


idf_component_register(
	SRCS
		"main.c"
		"device_settings.c"
		"lora_settings_handler.c"

		# Meshcore
		"meshcore/packet.c"
		"meshcore/chat/grp_payload.c"
		"meshcore/payload/ack.c"
		"meshcore/payload/advert.c"
		"meshcore/payload/grp_txt.c"
		"meshcore/payload/request.c"
		"crypto/aes.c"
		"crypto/sha256.c"
		"crypto/hmac_sha256.c"
		"ed25519/add_scalar.c"
		"ed25519/fe.c"
		"ed25519/ge.c"
		"ed25519/keypair.c"
		"ed25519/key_exchange.c"
		"ed25519/sc.c"
		"ed25519/seed.c"
		"ed25519/sha512.c"
		"ed25519/sign.c"
		"ed25519/verify.c"
	PRIV_REQUIRES
		esp_lcd
		fatfs
		nvs_flash
		bt
		badge-bsp
		tanmatsu-wifi
		${extra_requires}
	INCLUDE_DIRS
		"."
)

idf_build_set_property(COMPILE_OPTIONS "-Wno-error=unused-variable" APPEND)
idf_build_set_property(COMPILE_OPTIONS "-Wno-error=unused-const-variable" APPEND)
