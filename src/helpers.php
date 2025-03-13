<?php
// +----------------------------------------------------------------------
// | MICATEAM 
// +----------------------------------------------------------------------
// | Website: 
// +----------------------------------------------------------------------
// | Author:  <11247005@qq.com>
// +----------------------------------------------------------------------
use support\Db;
/**
* 生成指定长度 - 用于验证码
* 使用Base32字符集
* @param int $len 长度
*/
if(!function_exists('rand_base32')){
    function rand_base32($len=4)
    {
      return substr(str_shuffle("23456789ABCDEFGHJKLMNPQRSTUVWXYZ"),0,$len);
    }
}
/**
 * HMAC-based One-Time Password
 * 基于HMAC的一次性密码 RFC4226
 * otpauth://hotp/{label}?secret={secret}&issuer={issuer}
 */
if(!function_exists('useTOTP')){
  function useHOTP($secret,$step=30,$digits=6){
    // 获取当前时间戳并除以$timeStep（例如30秒）来得到计数器值
    $counter = floor(microtime(true) / $timeStep);

    // 将计数器转换为二进制字符串
    $time = pack('N*', 0) . pack('N*', $counter);

    // 计算HMAC-SHA1
    $hash = hash_hmac('sha1', $time, base64_decode($secret), true);

    // 获取offset
    $offset = ord(substr($hash, -1)) & 0xF;

    // 取最后4字节的数据并转换为整数
    $otp = (
        ((ord($hash[$offset + 0]) & 0x7F) << 24 ) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16 ) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8 ) |
        (ord($hash[$offset + 3]) & 0xFF)
    );

    // 我们只想要6位数字的OTP，所以取模10^6
    return str_pad($otp % 1000000, 6, '0', STR_PAD_LEFT);
  }
}
/**
 * Time-Based One-Time Password
 * 基于时间的一次性密码 RFC6238
 * otpauth://totp/{label}?secret={secret}&issuer={issuer}
 */
if(!function_exists('useTOTP')){
  function useTOTP(){

  }
}
/**
* Mysql实例 
* 推荐使用 模型
* [laravel数据库](https://github.com/illuminate/database)
*/
if(!function_exists('onMysql')){
    function onMysql($table)
    {
      return Db::table($table);
    }
}
/*
* Redis实例 - 配置文件读取默认
* 返回句柄
*/
if(!function_exists('onRedis')){
    function onRedis()
    {
      @['host'=>$host,'password'=>$password,'port'=>$port] = config('redis.default');
      $redis = new Redis;
      $redis->connect($host, $port);
      $password && $redis->auth($password);
      return $redis;
    }
}
/*
* Redis数组执行(自动close)
* runRedis('HGET',["wallet",$uuid])
* runRedis('HINCRBY',["wallet",$uuid,10])
*/
if(!function_exists('runRedis')){
    function runRedis($method,$params=[])
    {
      @['host'=>$host,'password'=>$password,'port'=>$port] = config('redis.default');
      $redis = new Redis;
      $redis->connect($host, $port);
      $password && $redis->auth($password);
      $data = $redis->$method(...$params);
      $redis->close();
      return $data;
    }
}
/*
* [webman-queue] 队列封装
* @param string $queue 队列名称
* @param array $data 数据
* @param int $delay 可选：延迟时间
*/
if(!function_exists('onQueue')){
    function onQueue($queue,$data,$delay=0)
    {
      $queue_waiting = '{redis-queue}-waiting';
      $queue_delay = '{redis-queue}-delayed';
      $now = time();
      $package_str = json_encode([
          'id'       => rand(),
          'time'     => $now,
          'delay'    => $delay,
          'attempts' => 0,
          'queue'    => $queue,
          'data'     => $data
      ]);
      return $delay ? onRedis()->zAdd($queue_delay, $now + $delay, $package_str) : onRedis()->lPush($queue_waiting.$queue, $package_str);
    }
}
/*
* [http-client] 异步网络请求封装
* @param string $url 请求网址
* @param array $options 请求配置
* 示例：'https://example.com/', ['method' => 'POST','version' => '1.1','headers' => ['Connection' => 'keep-alive'],'data' => ['key1' => 'value1', 'key2' => 'value2'],]
* 请求返回 返回 [JOSN] 非对象返回 [raw=响应内容]
* 错误返回 ['err'=>500,'msg'=>'错误信息']
*/
if(!function_exists('onRequest')){
    function onRequest($url,$options=[])
    {
      static $http;
      $http || $http = new Workerman\Http\Client([
        'max_conn_per_addr' => 128, // 每个域名最多维持多少并发连接
        'keepalive_timeout' => 15,  // 连接多长时间不通讯就关闭
        'connect_timeout'   => 30,  // 连接超时时间
        'timeout'           => 30,  // 请求发出后等待响应的超时时间
      ]);
      try {
        $response = $http->request($url, array_merge(['method' => 'GET','version' => '1.1'],$options));
        $boby = (string)$response->getBody();
        return json_decode($boby,true) ?? ['raw'=>$boby];
      } catch (\Exception $e) {
        return ['err'=>500,'msg'=>$e->getMessage];
      }
    }
}
/*
* HTTP代理网络请求 - 配置文件随机读取 [youloge.proxy[0~n]]
* 请求参数与 httpProxy == onRequest == http-client(request) 一样
* @param string $url 请求网址
* @param array $options 请求配置
*/
if(!function_exists('httpProxy')){
    function httpProxy($url,$options=[])
    {
        try {
            @['method'=>$method,'headers'=>$headers,'data'=>$data] = $options;
            $proxy = config('youloge.proxy'); $is_list = array_is_list($proxy); $is_list && shuffle($proxy);
            @[['addr'=>$addr,'port'=>$port,'pass'=>$pass]] = $is_list ? $proxy : [$proxy];
            $method = strtoupper($method ?? 'GET');$headers = ['Connection: keep-alive'];
            // 处理头信息
            if (is_object($header)) {
                foreach ($header as $key => $value) {
                    $headers[] = "$key: $value";
                }
            } elseif (is_array($header)) {
                $headers = array_merge($headers, $header);
            }
            //
            $curl = curl_init();
            curl_setopt_array($curl, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 0, 
                CURLOPT_HTTPHEADER=>$headers,
                CURLOPT_SSL_VERIFYPEER => 0,
                CURLOPT_SSL_VERIFYHOST => 0,
                // 代理配置
                CURLOPT_PROXY => $addr,
                CURLOPT_PROXYPORT => $port,
                CURLOPT_PROXYUSERPWD => $pass,
            ]);
            if($method == 'POST'){
                curl_setopt($curl, CURLOPT_POST, true);
                $data && curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
            }
            $response = curl_exec($curl);
            curl_close($curl);
            return json_decode($response,true) ?? ['raw'=>$response];
        } catch (\Throwable $th) {
            return ['err'=>500,'msg'=>$th->getMessage];
        }
    }
}
/**
 * 生成虚拟文件对象并上传 - 支持多文件
 * @param string $url 上传地址
 * @param array $files 文件类型数据 ['表单名称'=>['name'=>'文件名称','mime'=>'文件类型','data'=>'数据内容']]
 * @param array $body 其他表单数据
 * @param array $header 其他表单请求头
 * @return array 上传结果
 */
if(!function_exists('virtualFile')){
    function virtualFile($url,$files,$body=[],$header=[])
    {
        try {
            $headers = ['Content-Type: multipart/form-data'];$form = array_merge([],$body);$temps = [];
            if(is_object($header)){
                foreach ($header as $key => $value) {
                    $headers[] = "$key: $value";
                }
            }else{
                $headers = array_merge($headers,$header);
            }
            // 生成文件
            foreach($files as $key=>['name'=>$name,'mime'=>$mime,'data'=>$data]){
                $temp = tmpfile();@['uri'=>$uri] = stream_get_meta_data($temp);
                fwrite($temp, $data);
                $form[$key] = curl_file_create($uri,$mime,$name);
                $temps[] = $temp;
            }
            // 发送请求
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt_array($curl, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 0, 
                CURLOPT_POST => true,
                CURLOPT_SSL_VERIFYPEER => 0,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_POSTFIELDS => $form
            ]);
            $response = curl_exec($curl);
            curl_close($curl);
            // 关闭临时文件
            foreach ($temps as $temp) { fclose($temp); }
            return json_decode($response,true) ?? ['raw'=>$response];
        } catch (\Throwable $e) {
            return ['err'=>500,'msg'=>$e->getMessage()];
        }
    }
}
/**
 * =============================
 * = 算法相关
 * =============================
*/
/**
 * 安全的base64编码
 */
if(!function_exists('safe_base64_encode')){
    function safe_base64_encode($data){
      return str_replace(['+','/','='],['-','_',''],base64_encode($data));
    }
}
if(!function_exists('safe_base64_decode')){
    function safe_base64_decode($data){
      return base64_decode(str_replace(['-','_'],['+','/'],$data));
    }
}
/**
 * 构造腾讯云请求体 - 配置路径(一律小写)：[youloge.{appid}.secretid|secretkey]
 * 签名方法：TC3-HMAC-SHA256
 * @param string $method  请求方式 GET/POST
 * @param string $endpoint_action_version_region  接入点/方法/版本/区域 
 * trtc.tencentcloudapi.com/DescribeInstances/2019-07-22/ap-guangzhou
 * @param array $payload  请求载体 无参数时 设为[],null,false,0 即可
 * @param string $appid  选择那个商户id下得的证书
 */
if(!function_exists('tencent_request')){
  function tencent_request($method,$endpoint_action_version_region,$payload,$appid)
  {
    @['secretid'=>$SecretId,'secretkey'=>$SecretKey] = config("youloge.$appid");
    @[$Endpoint,$Action,$Version,$Region] =  $tencent = explode('/',$endpoint_action_version_region);
    @[$Server] = explode('.',$Endpoint);$data = $payload ? json_encode($payload,320) : '';$method = strtoupper($method);
    // 准备参数
    $Timestamp = time();
    $Timesdate = gmdate("Y-m-d",$Timestamp);
    $body_h256 = hash('SHA256',$data);
    // 第一步
    $request_h256 = hash('SHA256',"$method\n/\n\ncontent-type:application/json\nhost:$Endpoint\n\ncontent-type;host\n$body_h256");
    // 第二步
    $StringToSign = "TC3-HMAC-SHA256\n$Timestamp\n$Timesdate/$Server/tc3_request\n$request_h256";
    // 第三步
    $SecretDate = hash_hmac('SHA256', $Timesdate,"TC3$SecretKey", true);
    $SecretService = hash_hmac('SHA256',$Server,$SecretDate, true);
    $SecretSigning = hash_hmac('SHA256',"tc3_request",$SecretService, true);
    $Signature = hash_hmac('SHA256',$StringToSign,$SecretSigning);
    // 第四步
    $Authorization = "TC3-HMAC-SHA256 Credential=$SecretId/$Timesdate/$Server/tc3_request, SignedHeaders=content-type;host, Signature=$Signature";
    $header = [
      "Authorization"=>"$Authorization",
      "Content-Type"=>"application/json", // ; charset=utf-8
      "X-TC-Action"=>"$Action",
      "X-TC-Version"=>"$Version",
      "X-TC-Timestamp"=>"$Timestamp"
    ];
    $Region && $header['X-TC-Region'] = $Region;
    // 第五步
    return ["https://$Endpoint",[
        'method' => $method,
        'headers' => $header,
        'data' => $data,
      ]
    ];
  }
}
/**
 * 七牛签名 - 配置文件读取[youloge.qiniu.ak/sk]
 * qiniu_hmac 
 * 
 */
/**
 * 七牛HMAC - 
 * @param string $string 待签名字符串
 */
if(!function_exists('qiniu_hmac')){
    function qiniu_hmac($string)
    {
      @['ak'=>$AK,'sk'=>$SK] = config('youloge.qiniu');
      $sign =  str_replace(['+','/'],['-','_'],base64_encode(hash_hmac('sha1',$string,$SK,true)));
      return "$AK:$sign";
    }
}
/**
 * 七牛SIGN - 
 * @param array $params 待签名数组对象
 */
if(!function_exists('qiniu_sign')){
    function qiniu_sign($params)
    {
      $string = str_replace(['+','/'],['-','_'],base64_encode(json_encode($params)));
      $sign =  qiniu_hmac($string);
      return "$sign:$string";
    }
}
/**
 * 七牛AUTH - 
 * @param array $params 待签名数组对象
 */
if(!function_exists('qiniu_auth')){
    function qiniu_auth($params)
    {
      @['ak'=>$ak,'sk'=>$sk] = config('youloge.qiniu');
      $string = str_replace(['+','/'],['-','_'],base64_encode($params));
      $sign =  str_replace(['+','/'],['-','_'],base64_encode(hash_hmac('sha1',$string,$sk,true)));
      return ["Authorization: Qiniu $ak:$sign", "Content-Type: $type"];
    }
}
/**
 * 七牛DOWN - 
 * @param array $url 待签名下载网址
 * @param number $second 可选：设置有效时间 默认3600秒
 * @param string $attname 可选：设置下载文件名 默认没有
 */
if(!function_exists('qiniu_download')){
    function qiniu_download($url,$second=3600,$attname='')
    {
        @['scheme'=>$scheme,'host'=>$host,'path'=>$path,'query'=>$queryString] = parse_url($url);
        $queryString && parse_str($queryString,$query);
        $query['e'] = time() + $second;
        $uri = sprintf("%s://%s%s",$scheme,$host,$path);
        $query['token'] = qiniu_hmac(sprintf('%s?%s',$uri,http_build_query($query)));
        $attname && $query['attname'] = $attname;
        return $uri . '?' . http_build_query($query);
    }
}

/**
 * =============================
 * = 支付算法类 详细配置文件
 * = 证书路径 youloge.{$appid}.{apiclient_key}
 * = 证书格式 1. ./file.pem 文件路径 PEM编码的证书/私钥|公钥 2. PEM格式的私钥|公钥
 * =============================
*/
/***
 * 
 * 私钥签名 - 配置路径：[youloge.{appid}.apiclient_key]
 * @param string $string 待签名字符串
 * @param string $appid 选择那个id下得的证书
 * 返回数组 成功 [err=>200,data=>base64] 失败 [err=>500,msg=>'签名错误']
 */
if(!function_exists('private_sign')){
    function private_sign($string,$appid){
      try {
        @['apiclient_key'=>$apiclient_key] = config("youloge.$appid");
        openssl_sign($string, $raw_sign, openssl_pkey_get_private($apiclient_key), 'sha256WithRSAEncryption');
        return ['err'=>200,'data'=>base64_encode($raw_sign)];
      } catch (\Throwable $e) {
        return ['err'=>500,'msg'=>$e->getMessage()];
      }
    }
}
/***
 * 构造微信支付请求体 - 配置路径：[youloge.{appid}.apiclient_key|serial_no...]
 * 示例：weixin_request('GET','/v3/certificates',{},11111111);
 * 
 * @param string $method 请求网络方式 GET/POST
 * @param string $router 请求网络路径 必须'/'开头
 * @param array $data JSON数据 不传设置为 '' false 0 即可
 * @param string $appid 选择那个商户id下得的证书
 */
if(!function_exists('weixin_request')){
    function weixin_request($method,$router,$data='',$appid='')
    {
      @['apiclient_key'=>$apiclient_key,'serial_no'=>$serial_no] = config("youloge.$appid");$noncestr = session_create_id();$timestamp = (string)time(); 
      $body = $data ? json_encode($data,320): '';$method = strtoupper($method);
      
      openssl_sign("$method\n$router\n$timestamp\n$noncestr\n$body\n", $raw_sign, openssl_pkey_get_private($apiclient_key), 'sha256WithRSAEncryption');
      $sign = base64_encode($raw_sign);
      $authorization = sprintf('WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%d",serial_no="%s"',$appid, $noncestr,$sign, $timestamp, $serial_no);
  
      $header = [ 'accept'=>'application/json','authorization'=>$authorization,'User-Agent'=>'https://zh.wikipedia.org/wiki/User_agent','Content-Type'=>'application/json' ];
      // 返回请求体
      return [sprintf('https://api.mch.weixin.qq.com%s',$router),['method'=>$method,'headers'=>$header,'data'=>$body]];
    }
}
/**
 * 微信回调验签 - 配置路径：[youloge.{serial}.platform_cert]
 * @param object $request Request 给返回对象传进来
 * 成功返回 对象返回JSON 否则返回 []
 * 失败返回 ['err'=>500,'msg'=>Exception]
 */
if(!function_exists('weixin_verify')){
    function weixin_verify($request)
    {
      try{
        @['Wechatpay-Timestamp'=>$Timestamp,'Wechatpay-Nonce'=>$Nonce,'Wechatpay-Signature'=>$Signature,'Wechatpay-Serial'=>$Serial] = $request->header();
        @['platform_cert'=>$platform_cert] = config("youloge.$Serial");$rawBody = $request->getContent();
        $verify = (bool)openssl_verify("$Timestamp\n$Nonce\n$rawBody\n", base64_decode($Signature), openssl_get_publickey($platform_cert), 'sha256WithRSAEncryption');
        return $verify ? $request->all() : [];
      }catch(\Exception $e){
        return ['err'=>500,'msg'=>$e->getMessage()];
      }
    }
}
/**
 * 微信解密V3 - 配置路径：[youloge.{appid}.v3key]
 * @param array $encrypt 解密数据 要有['ciphertext','nonce','associated_data'] 
 * @param string $appid 选择那个商户id下得的证书
 * 成功返回 对象返回JSON 否则返回 ['raw'=>$raw]
 * 失败返回 ['err'=>500,'msg'=>Exception]
 */
if(!function_exists('weixin_decrypt')){
    function weixin_decrypt($encrypt,$appid)
    {
      try{
        @['v3key'=>$v3key] = config("youloge.$mchid");
        @['ciphertext'=>$ciphertext,'nonce'=>$nonce,'associated_data'=>$associated] = $encrypt;
        $cipher = base64_decode($ciphertext);
        $decrypt = openssl_decrypt(substr($cipher, 0, -16), 'aes-256-gcm', $v3key, OPENSSL_RAW_DATA, $nonce,substr($cipher, -16), $associated);
        return json_decode($decrypt,true) ?? ['raw'=>$decrypt];
      }catch(\Exception $e){
        return ['err'=>500,'msg'=>$e->getMessage()];
      }
    }
}

/**
 * 构造支付宝支付请求体 - 配置路径：[appid.{appid}.apiclient_key]
 * 示例：alipay_request('alipay.trade.create',$data,11111111);
 * @param string $method  接口名称 alipay.trade.create ...
 * @param array $data  待合并参数
 * @param string $appid  选择那个商户id下得的证书
 */
if(!function_exists('alipay_request')){
    function alipay_request($method,$data,$appid)
    {
      @['public'=>$public,$method=>$params] = config('youloge.alipay');
      @['apiclient_key'=>$apiclient_key] = config("youloge.$appid");
      $body = array_merge($public,$params??[],$data??[],['app_id'=>$appid,'method'=>$method]);
      ksort($body);
      openssl_sign(urldecode(http_build_query($body)), $raw_sign, openssl_pkey_get_private($apiclient_key), 'sha256WithRSAEncryption');
      $body['sign'] = base64_encode($raw_sign);;
        return [sprintf("https://openapi.alipay.com/gateway.do?%s",http_build_query($body)),[
          'method' => 'GET',
          'version' => '1.1',
          'headers' => ['accept' => 'application/json, text/plain, */*'],
          // 'data' => $body,
        ]
      ];
    }
}
/**
 * 支付宝验签 - 配置路径：[youloge.alipay.public_key]
 * @param object $request Request 给返回对象传进来
 * 成功返回 对象返回JSON 否则返回 []
 * 失败返回 ['err'=>500,'msg'=>Exception]
 */
if(!function_exists('alipay_verify')){
    function alipay_verify($request)
    {
      try{
        @['public_key'=>$alipay_public_key] = config('youloge.alipay');
        @['sign'=>$sign,'sign_type'=>$sign_type] = $params = $request->all();
        unset($params['sign']);unset($params['sign_type']);ksort($params);
        $verify = (bool)openssl_verify(urldecode(http_build_query($params)), base64_decode($sign), openssl_get_publickey($alipay_public_key), 'sha256WithRSAEncryption');
        return $verify ? $params : [];
      }catch(\Exception $e){
        return ['err'=>500,'msg'=>$e->getMessage()];
      }
    }
  }

/**
 * 读取配置文件参数
 * `ini(null)`返回全部配置 
 * `ini('MYSQL','默认值')` 返回一级配置[数组]
 * `ini('MYSQL.HOST')` 返回三级配置[字符串]
 */
if(!function_exists('ini')){
    function ini($keys, $def=''){
      static $config = [];
      if (!$config) {
        $config = @parse_ini_file(base_path().'/.env',true) ?? [];
      }
      if($keys === null){
        return $config;
      }
      @[$one,$two] = explode('.', $keys);
      @[$one=>$item] = $config;
      return $two === null ? $item ?? $def : $item[$two] ?? $def;
    }
  }