# Youloge.tool Webman 辅助函数工具箱

![Brightgreen](https://img.shields.io/badge/@-micateam-brightgreen.svg) ![Packagist](https://img.shields.io/packagist/v/youloge/webman.tool) ![Languages](https://img.shields.io/github/languages/top/youfeed/webman.tool.svg) ![Packagist Downloads](https://img.shields.io/packagist/dt/youloge/webman.tool) ![License ](https://img.shields.io/packagist/l/youloge/webman.tool)

> 使用前看一下下面辅助函数：尤其注意`函数名称问题`

- 代码风格极简 欢迎提交代码
- 几行代码就能接入微信支付/支付宝
- 一行代码生成一个虚拟文件并上传

### 项目地址

[Github Youloge.Tool](https://github.com/youfeed/webman.tool) Star 我 `有帮助的话，记得给个star` 能提交点代码最好

- 1.2.9 [2025-04-23] 增加`array_is_list`函数用于兼容低版本 PHP7.4+ 优化 [useValidate 验证器](https://www.workerman.net/plugin/188)
- 1.2.8 [2025-03-20] 增加`useValidate`基本数据类型`int:100`,`float:1.02`,`bool:false`,`string:默认值` 提供默认值支持
- 1.2.7 [2025-03-16] 优化表单过滤器`useValidate`并拆分独立版本[Webman.validate](https://www.workerman.net/plugin/188)
- 1.2.4 [`2025-03-15`] 新增输入过滤器`useValidate`优雅处理表单输入
- 1.2.2 [2025-03-13] 新增谷歌令牌辅助函数 `secret_base32` => `useTOTP`
- 1.0.1 增加 构造腾讯云请求体
- 0.0.9 迁移多个辅助函数

### 安装使用

> `composer require youloge/webman.tool`

- 如果要使用 `onRequest` 请求封装 请安装`composer require workerman/http-client`
- 如果要使用 `onQueue` 队列封装 请安装`composer require workerman/redis-queue`

### 使用说明

- 到目录`config/youloge.php` 新建配置文件
- 工具箱已经内置``[配置文件读取功能 .ini](https://www.workerman.net/plugin/153)

```php
<?php
$config = [
	'weixin'=>[
		'v3key'=>ini('WEIXIN.V3KEY',''),// 商户APIV3密钥,
		'anthor'=>'https://%s%S'
	],
	// 支付宝 二类配置`public`和`gatway.xxx.xxx.xx`
	'alipay'=>[
		// 公共参数
		'public'=>[
			'app_id'=>'','method'=>'','version'=>'1.0',
			'format'=>'JSON','charset'=>'utf-8',
			'sign_type'=>'RSA2','timestamp'=>date('Y-m-d H:i:s')
		]
		// 方法参数
		'alipay.system.oauth.token'=>['grant_type'=>'','code'=>""],
          'alipay.trade.create'=>['biz_content'=>'','notify_url'=>'',],
          'alipay.trade.precreate'=>['biz_content'=>'','notify_url'=>'',],
          'alipay.trade.page.pay'=>['notify_url'=>'','biz_content'=>''],
          'alipay.trade.wap.pay'=>['notify_url'=>'','biz_content'=>''],
	],
	// 数组每次代理 随机选择一个
	'proxy'=>[
		['addr'=>'','prot'=>'','pass'=>'']
	],
	// 商户配置
	'150123456'=>[
		'apiclient_key'=>'file:///www/pem/150123456.apiclient_key.pem'
	],
	// 小程序配置
	'12345678'=>[
		'secert'=>ini('XCX.SECERT','12345678'),
		'xxx'=>ini('XCX.xxx','12345678'),
	]
];
// 带格式的配置 - 例如
$config['150123456']['cert'] = <<<EOT
多行配置参数
多行配置参数
EOT;
// 最后返回配置
return $config;
```

## 示例代码 - 辅助辅助 函数还是要配合代码食用才香~

### 示例：`表单输入验证器` 查看使用详情文档 [webman.validat](https://www.workerman.net/plugin/edit/188)

- 验证规则
- - `|` 分割多个规则
- - `:` 规则参数 `,`多个参数用逗号分隔
- - `#` 自定义错误提示

```php
 $rules = [
 	'name'=>'required|min:3|max:10',
 	'age'=>'required|int|min:18|max:100',
 	'email'=>'required|email',
 ]
 $array = useValidate($data,$rules,$filter=true);
```

### 示例：`标准动态令牌`

> 标准 TOTP 令牌 RFC6238

```php
$secret = secret_base32(16); // 生成一个16位Base32随机字符串
$array = useTOTP('GQBWBS7AAEBECCUJ',1741877199);
// 返回时间戳 前中后 三组验证码
[893277,448721,854850]
```

### 示例：`腾讯云短信SMS号码查询`

> 简单粗暴 不需要安装各种`腾讯云各种SDK`配好密钥 直接开干

```php
    // 第二个参数为一个组合 `接入点/方法/版本/区域(可选参数)`
    $options = tencent_request('POST','sms.tencentcloudapi.com/DescribePhoneNumberInfo/2021-01-11/ap-nanjing',[
            'PhoneNumberSet'=>['+8617605509012']
        ],'1253985496');
    $request = onRequest(...$options); // 异步请求
    $request = httpProxy(...$options); // 代理请求
```

### 示例：`请求微信证书`

> 就是这么简单 发起 JSAPI H5 支付都是同理，比如 JSAPI 支付`统一下单之后`在调用一下签名组装一下`payment`参数即可支付

```php
$options = weixin_request('GET','/v3/certificates',[],'商户ID');
@['data'=>$data] = $request = onRequest(...$options);
// 返回一个V3加密后的数组
$list = [];
foreach($data as ['serial_no'=>$serial_no,'encrypt_certificate'=>$encrypt_certificate]){
	// 使用微信V3解密 weixin_decrypt
	$certificate = weixin_decrypt($encrypt_certificate,'商户ID');
	// 按照证书序列号`PEM格式`保存到本地
	file_put_contents("$serial_no.pem",$certificate);
	$list[$serial_no] = $certificate;
}
//
return $list;
```

### 示例：`上传JSON文件到七牛`

> 上传`一个JSON片段文件`并指定保存文件名到`config/100.json`, 二进制数据没测试\*

```php
     $url = qiniu_sign([
        'scope'=>"buket:100.json",
        'deadline'=>time()+300,
        'forceSaveKey'=>true,
        'saveKey'=>"config/100.json",
        'returnBody'=>'{"err": 200,"hash": $(etag)}',
        'insertOnly'=>0,
    ]);
    $data = json_encode([
        'uuid'=>100,
        'target'=>'https://www.abc.com',
        'type'=>'1'
    ]);
    $file = ['name'=>"100.json",'mime'=>'application/json','data'=>$data];
    @['err'=>$err,'hash'=>$hash] = $virtual = virtualFile("https://upload.qiniup.com/?token=$url",['file'=>$file],['key'=>'100']);
```

### 示例：`代理请求网网址`

> 网站支持`github登录`服务器在国内，运营商会屏蔽你的访问，这时候可以使用代理请求，数据结构与`onRequest` 一样

```php
    @['appid'=>$appid,'code'=>$code] = $request->all();
    @['secret'=>$secret] = config("youloge.$appid"); // 配置参数格式统一起来
    // 换取`access_token`
    @['access_token'=>$access_token] = $data = `httpProxy`(
    "https://github.com/login/oauth/access_token?client_id=$appid&client_secret=$secret&code=$code",[
      'headers'=>[
        'Accept'=>'application/json'
        ]
    ]);
    if($access_token == null){ return ['err'=>100800,'msg'=>'Github授权失败']; }
    // 获取用户信息
    @['email'=>$mail] = $data = httpProxy('https://api.github.com/user',[
      'headers'=>['Authorization'=>"Bearer $access_token",'Accept'=>'application/json','User-Agent'=>'Youloge-API']
    ]);
    if($mail == null){ return ['err'=>100801,'msg'=>'Github账户未认证']; }
    // 用登录信息 查询数据库 ...

```

---

## 代码工具箱

---

### 安全的 base64 编码

```php
safe_base64_encode($data);
safe_base64_decode($data);
```

### 生成不重复字符 - 用于验证码

- 使用 Base32 字符集 ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
- @param int $len=4 长度

```php
rand_base32($len=4)
```

### 生成重复的字符 - 用于密钥密码

- 使用 Base32 字符集
- @param int $len=16 长度
- @param string $prefix='' 前缀

```php
secret_base32($len=16,$prefix='')
```

### Mysql 实例

- 推荐使用 模型
- [laravel 数据库](https://github.com/illuminate/database)
- @param string $table 表名

```php
onMysql($table)
```

### Redis 实例 - 配置文件读取默认

- 返回句柄

```php
onRedis()
```

### Redis 数组执行(自动 close)

- runRedis('HGET',["wallet",$uuid])
- runRedis('HINCRBY',["wallet",$uuid,10])

```php
runRedis($method,$params)
```

### [webman-queue] 队列封装

- @param string $queue 队列名称
- @param array $data 数据
- @param int $delay 可选：延迟时间

```php
     onQueue($queue,$data,$delay=0)
```

### [http-client] 异步网络请求封装

- @param string $url 请求网址
- @param array $options 请求配置
- 示例：'https://example.com/', ['method' => 'POST','version' => '1.1','headers' => ['Connection' => 'keep-alive'],'data' => ['key1' => 'value1', 'key2' => 'value2'],]
- 请求返回 返回 [JOSN] 非对象返回 [raw=响应内容]
- 错误返回 ['err'=>500,'msg'=>'错误信息']

```php
     onRequest($url,$options=[])
```

---

网络代理 微信支付/支付宝 都需`config/youloge.php` 配置文件

---

### HTTP 代理网络请求 - 配置文件随机读取 [youloge.proxy[0~n]]

- 请求参数与 httpProxy == onRequest == http-client(request) 一样
- @param string $url 请求网址
- @param array $options 请求配置

```php
     httpProxy($url,$options=[])
```

### 生成虚拟文件对象并上传 - 支持多文件

- @param string $url 上传地址
- @param array $files 文件类型数据 ['表单名称'=>['name'=>'文件名称','mime'=>'文件类型','data'=>'数据内容']]
- @param array $body 其他表单数据
- @param array $header 其他表单请求头
- @return array 上传结果

```php
     virtualFile($url,$files,$body=[],$header=[])
```

---

- =============================
- = 算法相关
- =============================

---

### 构造腾讯云请求体 - 配置路径(一律小写)：[youloge.{appid}.secretid|secretkey]

- 签名方法：TC3-HMAC-SHA256
- @param string $method 请求方式 GET/POST
- @param string $endpoint_action_version_region 接入点/方法/版本/区域
- @param array $payload 请求载体 无参数时 设为[],null,false,0 即可
- @param string $appid 选择那个 appid 下得的证书

```php
   tencent_request($method,$endpoint_action_version_region,$payload,$appid)
   $method = POST
   // 接入点/方法/版本/区域(可选参数)
   trtc.tencentcloudapi.com/DescribeInstances/2019-07-22/ap-guangzhou
```

---

### 七牛签名 - 配置文件读取[youloge.qiniu.ak|sk]

### 七牛 HMAC

- @param string $string 待签名字符串

```php
     qiniu_hmac($string)
```

### \* 七牛 SIGN -

- @param array $params 待签名数组对象

```php
     qiniu_sign($params)
```

### 七牛 AUTH -

- @param array $params 待签名数组对象

```php
     qiniu_auth($params)
```

### 七牛 DOWN -

- @param array $url 待签名下载网址
- @param number $second 可选：设置有效时间 默认 3600 秒
- @param string $attname 可选：设置下载文件名 默认没有

```php
     qiniu_download($url,$second=3600,$attname='')
```

---

- =============================
- = 支付算法类 详细配置文件
- = 证书路径 youloge.{$appid}.{apiclient_key}
- = 证书格式 1. ./file.pem 文件路径 PEM 编码的证书/私钥|公钥 2. PEM 格式的私钥|公钥
- =============================

---

### 私钥签名 - 配置路径：[youloge.{appid}.apiclient_key]

- @param string $string 待签名字符串
- @param string $appid 选择那个 id 下得的证书
- 返回数组 成功 [err=>200,data=>base64] 失败 [err=>500,msg=>'签名错误']

```php
     private_sign($string,$appid)
```

### 构造微信支付请求体 - 配置路径：[youloge.{appid}.apiclient_key|serial_no...]

- 示例：weixin_request('GET','/v3/certificates',{},11111111);
- 配置文件格式要规范
- @param string $method 请求网络方式 GET/POST
- @param string $router 请求网络路径 必须'/'开头
- @param array $data JSON 数据 不传设置为 '' false 0 即可
- @param string $appid 选择那个商户 id 下得的证书

```php
     weixin_request($method,$router,$data='',$appid='')
```

### 微信回调验签 - 配置路径：[youloge.{serial}.platform_cert]

- @param object $request Request `给返回对象传进来`
- 成功返回 对象返回 JSON 否则返回 []
- 失败返回 ['err'=>500,'msg'=>Exception]

```php
     weixin_verify($request)
```

### 微信解密 V3 - 配置路径：[youloge.{appid}.v3key]

- @param array $encrypt 解密数据 要有['ciphertext','nonce','associated_data']
- @param string $appid 选择那个商户 id 下得的证书
- 成功返回 对象返回 JSON 否则返回 ['raw'=>$raw]
- 失败返回 ['err'=>500,'msg'=>Exception]

```php
     weixin_decrypt($encrypt,$appid)
```

### 构造支付宝支付请求体 - 配置路径：[appid.{appid}.apiclient_key]

- 示例：alipay_request('alipay.trade.create',$data,11111111);
- @param string $method 接口名称 alipay.trade.create ...
- @param array $data 待合并参数
- @param string $appid 选择那个商户 id 下得的证书

```php
     alipay_request($method,$data,$appid)
```

### 支付宝验签 - 配置路径：[youloge.alipay.public_key]

- @param object $request Request `给返回对象传进来`
- 成功返回 对象返回 JSON 否则返回 []
- 失败返回 ['err'=>500,'msg'=>Exception]

```php
     alipay_verify($request)
```

### 读取配置文件参数

- `ini(null)`返回全部配置
- `ini('MYSQL','默认值')` 返回一级配置[数组]
- `ini('MYSQL.HOST')` 返回三级配置[字符串]

```php
ini($keys, $def='')
```
