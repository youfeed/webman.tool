<?php

/**
 * 读取配置文件参数
 */
if(!function_exists('ini')){
  function ini($keys, $def='') : string
  {
      static $env_config = [];
      if (!$env_config) {
          $env_config = parse_ini_file(base_path().'/.env',true);
      }
      @[$one,$two] = explode('.', $keys);
      @[$one=>[$two=>$value]] = $env_config;
      return $value ?? $def;
  }
}
/**
 * 返回 base32 打乱字符串
 */
if(!function_exists('shuffle_base32')){
  function shuffle_base32($len=4)
  {
    return substr(str_shuffle("23456789ABCDEFGHJKLMNPQRSTUVWXYZ"),0,$len);
  }
} 
/*
* Redis 综合执行
* runRedis('HGET',["wallet",$uuid])
* runRedis('HINCRBY',["wallet",$uuid,10])
*/
if(!function_exists('runRedis')){
  function runRedis($method,$params)
  {
    @['host'=>$host,'password'=>$password,'port'=>$port,'database'=>$database] = config('redis.default');
    $redis = new Redis;
    $redis->connect($host, $port);
    $password && $redis->auth($password); // 默认 null
    $database && $redis->select($database); // 默认 0表
    $data = $redis->$method(...$params);
    $redis->close();
    return $data;
  }
}
/**
 * Queue 投递消息到队列
 * 依赖 webman/redis-queue
 */
if(!function_exists('runQueue')){
  function runQueue($queue,$data,$delay=0)
  {
    $_waiting = '{redis-queue}-waiting';
    $_delay = '{redis-queue}-delayed';
    $now = time();
    $package = json_encode([
        'id'       => rand(),
        'time'     => $now,
        'delay'    => $delay,
        'attempts' => 0,
        'queue'    => $queue,
        'data'     => $data
    ]);
    if ($delay) {
        return runRedis('zAdd',[$_delay,$now + $delay,$package]);
    }
    return runRedis('lPush',[$_waiting.$queue,$package])->lPush($queue_waiting.$queue, $package);
  }
}
/**
 * 请求外部接口
 * 依赖 webman/http-client
 * 'https://example.com/'
 * [
 *   'method' => 'POST',
 *   'version' => '1.1',
 *   'headers' => ['Connection' => 'keep-alive'],
 *   'data' => ['key1' => 'value1', 'key2' => 'value2']
 * ]
 */
if(!function_exists('runRequest')){
  function runRequest($url,$options)
  {
    $http = new Workerman\Http\Client();
    $body = (string)$http->request($url,$options)->getBody();
    return json_decode($body,true) ?? $body;
  }
}
/**
 * 针对runRequest进行特定请求封装
 * JSONRPC youloge.rpc 请求
 * MEILISEARCH 美丽搜索引擎 请求
 * 
 */