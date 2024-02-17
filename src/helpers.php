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
    $redis = new Redis;
    $redis->connect('127.0.0.1', 6379);
    $data = $redis->$method(...$params);
    $redis->close();
    return $data;
  }
}