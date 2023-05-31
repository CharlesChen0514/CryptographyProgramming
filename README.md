# 方案设计

## 场景一：第一步：得到加密数

通过用户输入的 key 进行两次 Enigma 机的加密，获得大小数 d1 和 d2

![](figs/d1d2.png)

## 场景一：第二步：得到基数 D

- MPC-Main 随机生成信息的传递路径
- 根据路径传递 d + R 的累加值
- 传递完成后，每个用户上报自己的随机数
- MPC-Main 将随机数减去获得 d 的累加值
- 重复两次以上操作获得 d1 和 d2 的累加值，sumD1 和 sumD2

这样能够保证用户的 d1 和 d2 在传递的过程中不暴露，从而保证的自己的 key 的安全性

![](figs/baseD.png)

## 场景一：第三步：生成公钥和私钥

将 128 位的 sumD1 和 sumD2 等比例扩充到 1024 位

![](figs/padding.png)

通过 Miller-Rabin 素性测试找到素数 P 和 Q，生成 RSA 公私钥

![](figs/rsa.png)

## 场景一：第四步：可靠存储

组标识生成逻辑：格式为 ”用户数量@userName1@userName2...“

私钥存储流程：

- 根据用户数量将私钥划分成若干个私钥碎片
- 每个私钥碎片通过 [Reed Solomon](https://github.com/RobinLiew/JavaReedSolomon) 纠删码进行冗余存储，分为 4 个数据块和 2 个校验块
- 将数据块和校验块平均存储到三个存储商当中，能够保证一个存储商倒闭不影响业务

![](figs/priKeyStore.png)

存储形式：

- 组标识 -> 公钥
- （组标识，用户名）-> 私钥碎片
- 公钥和私钥碎片都通过 Reed Solomon 进行存储，包含 4 个数据块和 2 个校验块

磁盘利用率：4/(4+2)=2/3

![](figs/diskUseRate.png)

## 场景二：共同签名，自动验证签名

关键点：

- SignServer 自己有 RSA key，用户对 SignServer 进行请求的消息经过公钥加密传输，保证通道的安全性
- 签名请求只有等到授权人数达到组人数才会发送给区块链系统

![](figs/scenario2.png)

## 场景三：任意两个存储商倒闭（部分数据在），恢复密钥

核心思想：将恢复的公私钥转换成数据块，判断剩余存储商中的数据块是否有匹配块，匹配成功则说明恢复正确，反之恢复失败

![](figs/recover.png)


## 测试

### 场景一：第一步：得到加密数

测试 jar 包：Scenario1Test

![](figs/getEncryptedNumber.png)

- 首先两个用户会生成自己的 128 位的随机数 R
- 然后每个用户输入的 key，通过 Enigma 机加密两次获得 d1 和 d2

在该测试场景下，Alice 的 key 为 abcdefgh，Bob 的 key 为 ijklmnop

### 场景一：第二步：得到基数 D

![](figs/getBaseDTestImg.png)

首先通过 MPC-Main 随机生成传递路径，这里是 Bob -> Alice，图中显示了在传递过程中 X 值的变化。

最后每个用户上传自己的 R 值，MPC-Main 则得到各个用户的 d1 和 d2 的累加值

### 场景一：第三步：生成公钥和私钥

![](figs/generateRSAkeysTestImg.png)

首先展示了 sumD1 和 sumD2 扩展到 1024 位的结果，然后输出了找到 P 和 Q 的值，该场景下生成对应的公钥和私钥如下

```java
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK9wAAAAAAAYw7AAAAAAACRZgAAAAAAALtSgAA
AAAAA6NmAAAAAAAEU+8AAAAAAAUPpAAAAAAABbWVAAAAAAGu7yYAAAAAAaBeHQAAAAABlqVQAAAA
AAGFHPsAAAAAAX4iZQAAAAABd+7uAAAAAAGaJT0AAAAAAYTyAAAAAABKtQIDAQAB

MIIBNgIBADANBgkqhkiG9w0BAQEFAASCASAwggEcAgEAAoGBAMr3AAAAAAABjDsAAAAAAAJFmAAA
AAAAAu1KAAAAAAADo2YAAAAAAART7wAAAAAABQ+kAAAAAAAFtZUAAAAAAa7vJgAAAAABoF4dAAAA
AAGWpVAAAAAAAYUc+wAAAAABfiJlAAAAAAF37u4AAAAAAZolPQAAAAABhPIAAAAAAEq1AgEAAoGA
CEsrjtRxK47kogyP83AMkAsz+NwHI/jcJcIeWeGmHloHtUVOurFFTuf3HjLhzR4zFr6G2Xkmhtm0
38/OMDHP37l3zgwx884dI0xCEb3uQiJJ8hDt7xIQ/cR/pTJazaVB5p078MQPPAAPP3h0h4t4hTgW
cAeP+HAXY7lURqu5V0ECAQACAQACAQACAQACAQA=
```

### 场景一：第四步：可靠存储

![](figs/reliableStoreTestImg.png)

首先通过 MPC-Main 生成组标识，然后将公私钥和组标识传递给存储商进行存储。图中展示了私钥切片的结果
