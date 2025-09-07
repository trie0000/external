# 構成図解析レポート（input.xlsx / Sheet2）

## サマリ
- 図形数: 7
- ゾーン候補: 2
- ノード数（非コネクタ・ラベル除外）: 3
- エッジ数（コネクタ+疑似）: 2

## ゾーン（人間ラベル）
- `Rectangle 5`: **AWSクラウド** rect=(150,104,463,370)
- `Rectangle 1`: **VPC** rect=(173,158,451,358)

## ゾーン階層
- Rectangle 5: depth=0 parent=- children=1
- Rectangle 1: depth=1 parent=Rectangle 5 children=0

## ゾーン重なり
- Rectangle 5 ⟂ Rectangle 1 (overlap)

## ノードのゾーン割当（人間ラベルで表示）
- node=`Rectangle 2` → zone=`VPC` (conf=high, overlap=1.0, role=web) text='Webサーバ1' src=TextFrame2.debug note=
- node=`Rectangle 3` → zone=`AWSクラウド` (conf=high, overlap=1.0) text='インターネットGW' src=TextFrame2.debug note=
- node=`Rectangle 4` → zone=`Internet` (conf=high, overlap=0.0) text='ユーザ' src=TextFrame2.debug note=auto-reassigned-to-internet

## エッジ推定
- edge=`Straight Arrow Connector 6` kind=connector Rectangle 4 -> Rectangle 3 (dir_hint=src_to_dst, conf=high, proto=unknown (), zones=Internet->AWSクラウド)
- edge=`Straight Arrow Connector 9` kind=connector Rectangle 3 -> Rectangle 2 (dir_hint=src_to_dst, conf=high, proto=unknown (), zones=AWSクラウド->VPC)

## 越境通信（ゾーン間エッジ）
- Straight Arrow Connector 6: Rectangle 4@Internet -> Rectangle 3@AWSクラウド, proto=unknown()
- Straight Arrow Connector 9: Rectangle 3@AWSクラウド -> Rectangle 2@VPC, proto=unknown()