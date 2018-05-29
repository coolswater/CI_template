<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Welcome extends MY_controller {
    public function __construct() {
        parent::__construct();
    }
    
    public function index() {
        $ip = '127.0.0.1';
        echo getClientIp();
        $this->load->view('welcome_message');
    }
}
