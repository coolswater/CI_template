<?php
if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

/**
 * author: hexiaodong
 * Date: 2018/5/29
 */
class MY_controller extends CI_Controller {
    public function __construct() {
        parent::__construct();
        $this->is_my();
    }
    
    public function is_my() {
        echo '我是父类控制器';
    }
}