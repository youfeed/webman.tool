<?php

if(!function_exists('ini')){
    function ini($key, $val) : string
    {
        static $env_config = [];
        print_r(count($env_config));
        if (!$env_config) {
            print_r('$env_config');
            $env_config = parse_ini_file(base_path().'/.env',true);
        }
        return $env_config[$key][$val]??null;
    }
}