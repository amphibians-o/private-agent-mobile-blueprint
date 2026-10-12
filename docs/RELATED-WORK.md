# 関連プロジェクトと公開意義

公式READMEを短時間で確認した例。独立したコード監査、インストール、互換性検査はしていない。検索は網羅的でなく、世界に同等物が無いとは主張しない。

| プロジェクト | READMEから確認した範囲 | 本稿との関係 |
|---|---|---|
| willscott-v2/hermes-mobile-pwa | スマホPWAのthin client、RESTとWebSocket JSON-RPC、モックとテスト [9] | モバイルUIという目的が重なる。再利用候補として調査できる |
| luckeyfaraday/hermes-mobile | 同一originの中継、PWA/任意Electron、Tailscale Serve。対象はgateway api_server REST+SSEでDesktopプロセスのdashboard WSではない [10] | 「Hermesスマホ対応」でも接続対象が違う。正規Desktopのlive会話共有と同等とは断定しない |
| AlpinDale/ssh-dashboard | SSHサーバーのGPU/CPU監視、NVIDIA/AMD対応をREADMEで表明 [11] | GPU監視の既存例。導入前にはSSH鍵の権限と表示データを別途監査 |

提案する公開価値は「新しいスマホアプリが世界初」ではなく、次の判断と試験をLLM構築時に渡せること：

- ドライブ配信とagent自身のファイル権限の違い。
- ネットワーク制限とアプリ端末認証の違い。
- 別バックエンドのスマホチャットと、同一正規live会話への接続の違い。
- 閲覧、保存会話再開、本人確認付き引き継ぎ、実推論を分けた受入条件。
- 秘密をLLMへ渡さないローカル設定境界と、公開ファイルの許可リスト。
- 読み取り専用GPU監視、古い値/未取得表示、サービス停止を含めない運用。

本稿は上記プロジェクトのコードをコピー/フォークせず、説明と参照だけを含む。導入候補として採る場合はライセンスと正規API互換性を改めて確認する。

参照番号の出典は `SOURCES.md`。
