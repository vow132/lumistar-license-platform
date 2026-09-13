// 最小接入示例：初始化 → 激活 → 心跳 → 功能门禁。
// 可选演示编译期公钥固定：第 4 个参数传服务器 Ed25519 公钥（base64url，
// 由服务端 cmd/pubkeys 导出），pin 到 "sign-a"（演示用单密钥；正式宿主
// 按 cmd/pubkeys 输出的 kPinnedKeys 数组配置全部密钥）。
#include <lumistar/license_sdk.h>
#include <stdio.h>
#include <windows.h>
#include <string.h>

static void on_state(vft_state_t state, void *user) {
	(void)user;
	const char *s = "unknown";
	switch (state) {
	case VFT_STATE_ACTIVE: s = "ACTIVE"; break;
	case VFT_STATE_STALE: s = "STALE（心跳失联）"; break;
	case VFT_STATE_REVOKED: s = "REVOKED（服务端已处置）"; break;
	case VFT_STATE_ERROR: s = "ERROR"; break;
	default: s = "NOT_ACTIVATED"; break;
	}
	printf("[state] %s\n", s);
}

// 最小 base64url 解码（演示用；out 需 ≥32 字节），成功返回 true。
static bool b64url32(const char *in, unsigned char out[32]) {
	int acc = 0, bits = 0, n = 0;
	for (const char *c = in; *c && n < 32; c++) {
		int v = *c;
		if (v >= 'A' && v <= 'Z') v -= 'A';
		else if (v >= 'a' && v <= 'z') v -= 'a' - 26;
		else if (v >= '0' && v <= '9') v += 52 - '0';
		else if (v == '-') v = 62;
		else if (v == '_') v = 63;
		else return false;
		acc = (acc << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[n++] = (unsigned char)((acc >> bits) & 0xff);
		}
	}
	return n == 32;
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	if (lumistar_selftest() != VFT_OK) {
		printf("selftest FAILED\n");
		return 1;
	}
	printf("selftest ok (X25519/Ed25519/AES-GCM)\n");

	const char *server = argc > 1 ? argv[1] : "https://127.0.0.1:8080";
	const char *card = argc > 2 ? argv[2] : "";
	bool insecure_dev_only = false;
	const char *pinPubB64 = nullptr;
	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--insecure-dev-only") == 0) insecure_dev_only = true;
		else pinPubB64 = argv[i];
	}

	vft_config cfg = {};
	vft_pin_entry pins[1] = {};
	unsigned char pub[32] = {};
	if (pinPubB64) {
		if (!b64url32(pinPubB64, pub)) {
			printf("invalid pin pubkey (need 32-byte base64url)\n");
			return 1;
		}
		pins[0].kid = "sign-a"; // 与服务器 VFT_SIGN_ACTIVE_KID 一致
		memcpy(pins[0].pub, pub, 32);
		cfg.pin_entries = pins;
		cfg.pin_entries_len = 1;
		printf("pinned server key: sign-a (compile-time trust anchor)\n");
	}
	cfg.server_url = server;
	cfg.product_code = "AUXPRO";
	cfg.client_version = "1.0.0";
	cfg.insecure_skip_tls_verify = insecure_dev_only ? 1 : 0;
	if (insecure_dev_only) {
		printf("WARNING: TLS certificate verification is disabled for local development only.\n");
	}
	// cfg.storage_dir = "D:\\data\\lumistar";  // 默认 %PROGRAMDATA%\Lumistar\AUXPRO

	lumistar::License lic;
	vft_err_t ierr = lic.init(cfg);
	if (ierr != VFT_OK) {
		printf("init failed: %s (code=%d)\n", lumistar_err_str(ierr), ierr);
		return 1;
	}

	if (card[0]) {
		vft_activation_result r = {};
		vft_err_t err = lic.activate(card, &r);
		if (err == VFT_OK) {
			printf("activated: license=%s device=%s\n", r.license_id, r.device_id);
		} else {
			printf("activate failed: %s\n", lumistar_err_str(err));
			return 1;
		}
	} else if (lic.state() == VFT_STATE_NOT_ACTIVATED) {
		printf("usage: activate_demo <server_url> <card> [--insecure-dev-only] [pin_pubkey_b64url]\n");
		return 1;
	}

	lic.start_heartbeat(on_state, nullptr);

	// 业务功能门禁示例（每次调用实时验签，无本地放宽）
	for (int i = 0; i < 3; i++) {
		printf("feature[aimbot]=%d feature[esp]=%d lease_remaining=%llds\n",
		       lic.has_feature("aimbot"), lic.has_feature("esp"),
		       (long long)lic.lease_remaining());
		Sleep(2000);
	}

	lic.stop_heartbeat();
	return 0;
}
