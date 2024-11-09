# Youloge.tool Webman 辅助函数百宝箱

> 使用前看一下下面辅助函数：尤其注意`函数名称问题`

- 代码风格极简 欢迎提交代码 
- 几行代码就能接入微信支付/支付宝
- 一行代码生成一个虚拟文件并上传

### 项目地址

[Github Youloge.Tool](https://github.com/youfeed/webman.tool) Star我 `有帮助的话，记得给个star` 能提交点代码最好

- 0.0.9 迁移多个辅助函数
- 1.0.1 增加 构造腾讯云请求体

###  安装使用

> `composer require youloge/webman.tool`

### 使用说明
- 到目录`config/youloge.php` 新建配置文件
``` php
<?php
$config = [
	'weixin'=>[
		'v3key'=>'',
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
		'secert'=>'xxxxxx',
		'xxx'=>'xxx'
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

### 示例代码 - 辅助辅助 函数还是要配合代码食用才香~

### 示例：`请求微信证书`
> 就是这么简单 发起JSAPI H5 支付都是同理 
```
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
> 上传`一个JSON片段文件`并指定保存文件名到`config/100.json` 
```
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
```
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
### 

---
代码工具箱

---

### 生成指定长度 - 用于验证码
* 使用Base32字符集
* @param int $len 长度

```
rand_base32($len=4)
```

### Mysql实例
* 推荐使用 模型
* [laravel数据库](https://github.com/illuminate/database)
* @param string $table 表名

```
onMysql($table)
```

### Redis实例 - 配置文件读取默认
* 返回句柄

```
onRedis()
```

### Redis数组执行(自动close)
* runRedis('HGET',["wallet",$uuid])
* runRedis('HINCRBY',["wallet",$uuid,10])

```
runRedis($method,$params)
```

### [webman-queue] 队列封装
* @param string $queue 队列名称
* @param array $data 数据
* @param int $delay 可选：延迟时间

```
     onQueue($queue,$data,$delay=0)
```

### [http-client] 异步网络请求封装
* @param string $url 请求网址
* @param array $options 请求配置
* 示例：'https://example.com/', ['method' => 'POST','version' => '1.1','headers' => ['Connection' => 'keep-alive'],'data' => ['key1' => 'value1', 'key2' => 'value2'],]
* 请求返回 返回 [JOSN] 非对象返回 [raw=响应内容]
* 错误返回 ['err'=>500,'msg'=>'错误信息']

```
     onRequest($url,$options=[])
```

---
网络代理 微信支付/支付宝 都需`config/youloge.php` 配置文件

---

### HTTP代理网络请求 - 配置文件随机读取 [youloge.proxy[0~n]]
* 请求参数与 httpProxy == onRequest == http-client(request) 一样
* @param string $url 请求网址
* @param array $options 请求配置

```
     httpProxy($url,$options=[])
```


 ### 生成虚拟文件对象并上传 - 支持多文件
 * @param string $url 上传地址
 * @param array $files 文件类型数据 ['表单名称'=>['name'=>'文件名称','mime'=>'文件类型','data'=>'数据内容']]
 * @param array $body 其他表单数据
 * @param array $header 其他表单请求头
 * @return array 上传结果

```
     virtualFile($url,$files,$body=[],$header=[])
```

---

 * =============================
 * = 算法相关
 * =============================
---

### 安全的base64编码

```
safe_base64_encode($data);
safe_base64_decode($data);
```

### 构造腾讯云请求体 - 配置路径(一律小写)：[youloge.{appid}.secretid|secretkey]
* 签名方法：TC3-HMAC-SHA256
* @param string $method  请求方式 GET/POST
* @param string $endpoint_action_version_region  接入点/方法/版本/区域 
* @param array $payload  请求载体 无参数时 设为[],null,false,0 即可
* @param string $appid  选择那个appid下得的证书

```
   tencent_request($method,$endpoint_action_version_region,$payload,$appid)
   $method = POST
   // 接入点/方法/版本/区域(可选参数)
   trtc.tencentcloudapi.com/DescribeInstances/2019-07-22/ap-guangzhou
```


### 七牛签名 - 配置文件读取[youloge.qiniu.ak|sk]

>

### 七牛HMAC 

* @param string $string 待签名字符串

```
     qiniu_hmac($string)
```

### * 七牛SIGN - 
* @param array $params 待签名数组对象

```
     qiniu_sign($params)
```

### 七牛AUTH - 
* @param array $params 待签名数组对象

```
     qiniu_auth($params)
```

### 七牛DOWN - 
* @param array $url 待签名下载网址
* @param number $second 可选：设置有效时间 默认3600秒
* @param string $attname 可选：设置下载文件名 默认没有

```
     qiniu_download($url,$second=3600,$attname='')
```


---

 * =============================
 * = 支付算法类 详细配置文件
 * = 证书路径 youloge.{$appid}.{apiclient_key}
 * = 证书格式 1. ./file.pem 文件路径 PEM编码的证书/私钥|公钥 2. PEM格式的私钥|公钥
 * =============================

---

### 私钥签名 - 配置路径：[youloge.{appid}.apiclient_key]
* @param string $string 待签名字符串
* @param string $appid 选择那个id下得的证书
* 返回数组 成功 [err=>200,data=>base64] 失败 [err=>500,msg=>'签名错误']

```
     private_sign($string,$appid){
```
### 构造微信支付请求体 - 配置路径：[youloge.{appid}.apiclient_key|serial_no...]
* 示例：weixin_request('GET','/v3/certificates',{},11111111);
* 配置文件格式要规范
* @param string $method 请求网络方式 GET/POST
* @param string $router 请求网络路径 必须'/'开头
* @param array $data JSON数据 不传设置为 '' false 0 即可
* @param string $appid 选择那个商户id下得的证书

```
     weixin_request($method,$router,$data='',$appid='')
```
### 微信回调验签 - 配置路径：[youloge.{serial}.platform_cert]
* @param object $request Request `给返回对象传进来`
* 成功返回 对象返回JSON 否则返回 []
* 失败返回 ['err'=>500,'msg'=>Exception]

```
     weixin_verify($request)
```

### 微信解密V3 - 配置路径：[youloge.{appid}.v3key]
* @param array $encrypt 解密数据 要有['ciphertext','nonce','associated_data'] 
* @param string $appid 选择那个商户id下得的证书
* 成功返回 对象返回JSON 否则返回 ['raw'=>$raw]
* 失败返回 ['err'=>500,'msg'=>Exception]

```
     weixin_decrypt($encrypt,$appid)
```

### 构造支付宝支付请求体 - 配置路径：[appid.{appid}.apiclient_key]
* 示例：alipay_request('alipay.trade.create',$data,11111111);
* @param string $method  接口名称 alipay.trade.create ...
* @param array $data  待合并参数
* @param string $appid  选择那个商户id下得的证书

```
     alipay_request($method,$data,$appid)
```

### 支付宝验签 - 配置路径：[youloge.alipay.public_key]
* @param object $request Request `给返回对象传进来`
* 成功返回 对象返回JSON 否则返回 []
* 失败返回 ['err'=>500,'msg'=>Exception]

```
     alipay_verify($request)
```

### 读取配置文件参数
* `ini(null)`返回全部配置 
* `ini('MYSQL','默认值')` 返回一级配置[数组]
* `ini('MYSQL.HOST')` 返回三级配置[字符串]

```
ini($keys, $def='')
```


