// pubkeys 导出服务器的 Ed25519 签名公钥，供客户端 SDK 编译期固定（pin_entries）。
// 只输出公钥，绝不输出私钥种子；从 VFT_SIGN_KEYS 环境变量读取密钥材料。
//
// 用法（在 apps/license-api 下，已 source 密钥环境）：
//
//	go run ./cmd/pubkeys                # 输出 C 代码片段与 base64url 公钥
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func main() {
	raw := os.Getenv("VFT_SIGN_KEYS")
	if raw == "" {
		die(fmt.Errorf("VFT_SIGN_KEYS not set (source your key env first)"))
	}
	active := os.Getenv("VFT_SIGN_ACTIVE_KID")
	fmt.Println("// 由 cmd/pubkeys 生成；把下面的数组填入 vft_config.pin_entries。")
	fmt.Println("// 注意：轮换服务器密钥后需重新导出并发布新版客户端。")
	fmt.Println("static const vft_pin_entry kPinnedKeys[] = {")
	for _, seg := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(seg), ":", 2)
		if len(kv) != 2 {
			die(fmt.Errorf("bad segment %q", seg))
		}
		kid, seedB64 := kv[0], strings.TrimSuffix(kv[1], "*")
		seed, err := base64.RawURLEncoding.DecodeString(seedB64)
		if err != nil || len(seed) != ed25519.SeedSize {
			die(fmt.Errorf("bad seed for %s", kid))
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		mark := ""
		if kid == active {
			mark = "  // 当前签名密钥"
		}
		fmt.Printf("\t{ \"%s\", { %s } },%s\n", kid, hexBytes(pub), mark)
		fmt.Printf("// %-8s pub(b64url) = %s\n", kid, base64.RawURLEncoding.EncodeToString(pub))
	}
	fmt.Println("};")
}

func hexBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(parts, ", ")
}
