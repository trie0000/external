# 構成図解析レポート（input.xlsx / Sheet3）

## サマリ
- 図形数: 19
- ゾーン候補: 9
- ノード数（非コネクタ・ラベル除外）: 5
- エッジ数（コネクタ+疑似）: 5

## ゾーン（text_raw と resource_* 参考情報）
- `Rectangle 2`: **10.10.0.0/16** rect=(159,230,584,540) normalized=NETWORKING ai_label=VPC (cat=NETWORKING, conf=0.8)
- `Rectangle 3`: **Availabillty Zone** rect=(183,259,350,517) normalized=ZONE ai_label=AVAILABILITY_ZONE (cat=ZONE, conf=0.7)
- `Rectangle 4`: **Availabillty Zone** rect=(381,259,548,517) normalized=ZONE ai_label=AVAILABILITY_ZONE (cat=ZONE, conf=0.7)
- `Rectangle 5`: **Public subnet** rect=(196,314,327,391) normalized=ZONE ai_label=PUBLIC_SUBNET (cat=ZONE, conf=0.9)
- `Rectangle 7`: **Public subnet** rect=(403,313,534,390) normalized=ZONE ai_label=PUBLIC_SUBNET (cat=ZONE, conf=1.0)
- `Rectangle 1`: **AWS** rect=(142,131,624,564) normalized=ZONE ai_label=AWS_CLOUD_ZONE (cat=ZONE, conf=0.95)
- `Rectangle 6`: **Private subnet** rect=(195,409,327,486) normalized=ZONE ai_label=PRIVATE_SUBNET (cat=ZONE, conf=1.0)
- `Rectangle 8`: **Private subnet** rect=(402,408,534,485) normalized=ZONE ai_label=PRIVATE_SUBNET (cat=ZONE, conf=1.0)
- `Cloud Callout 10`: **InterNet** rect=(303,39,432,102) normalized=ZONE ai_label=INTERNET_ZONE (cat=ZONE, conf=1.0)

## ゾーン階層
- Rectangle 1: depth=0 parent=- children=1
- Cloud Callout 10: depth=0 parent=- children=0
- Rectangle 2: depth=1 parent=Rectangle 1 children=2
- Rectangle 3: depth=2 parent=Rectangle 2 children=2
- Rectangle 4: depth=2 parent=Rectangle 2 children=2
- Rectangle 5: depth=3 parent=Rectangle 3 children=0
- Rectangle 7: depth=3 parent=Rectangle 4 children=0
- Rectangle 6: depth=3 parent=Rectangle 3 children=0
- Rectangle 8: depth=3 parent=Rectangle 4 children=0

## ノードのゾーン割当（人間ラベルで表示）
- node=`Rectangle 9` → zone=`AWS` (conf=high, overlap=1.0) text='Internet gateway' src=TextFrame2.debug note=
- node=`Rectangle 11` → zone=`Public subnet` (conf=high, overlap=1.0) text='Nat gateway' src=TextFrame2.debug note=
- node=`Rectangle 12` → zone=`Private subnet` (conf=high, overlap=1.0) text='EC2' src=TextFrame2.debug note=
- node=`Rectangle 13` → zone=`Private subnet` (conf=high, overlap=1.0) text='EC2' src=TextFrame2.debug note=
- node=`Rectangle 14` → zone=`Public subnet` (conf=high, overlap=1.0) text='EC2' src=TextFrame2.debug note=

## エッジ推定
- edge=`Straight Connector 16` kind=connector Rectangle 14 -> Rectangle 11 (dir_hint=src_to_dst, conf=high, proto=unknown (), zones=Public subnet->Public subnet)
- edge=`Straight Connector 17` kind=connector Rectangle 13 -> Rectangle 11 (dir_hint=src_to_dst, conf=high, proto=unknown (), zones=Private subnet->Public subnet)
- edge=`Straight Connector 20` kind=connector Rectangle 12 -> Rectangle 11 (dir_hint=src_to_dst, conf=high, proto=unknown (), zones=Private subnet->Public subnet)
- edge=`Straight Connector 24` kind=connector Rectangle 9 ->  (dir_hint=src_to_dst, conf=medium, proto=unknown (), zones=AWS->(不明))
- edge=`Straight Connector 25` kind=connector Cloud Callout 10 -> Rectangle 9 (dir_hint=src_to_dst, conf=high, proto=unknown (), zones=(不明)->AWS)

## 越境通信（ゾーン間エッジ）
- Straight Connector 16: Rectangle 14@Public subnet -> Rectangle 11@Public subnet, proto=unknown()
- Straight Connector 17: Rectangle 13@Private subnet -> Rectangle 11@Public subnet, proto=unknown()
- Straight Connector 20: Rectangle 12@Private subnet -> Rectangle 11@Public subnet, proto=unknown()