<?php

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