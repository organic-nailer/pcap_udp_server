# pcap_udp_server

LiDARのpcapファイルを再生します

# 使い方

```
cargo run -- [filename]
```

255.255.255.255:8080にブロードキャストされます。

# Options

- `-p`, `--port`: ポートを指定
- `-r`, `--repeat`: 無限ループさせる
