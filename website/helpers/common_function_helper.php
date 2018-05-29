<?php
/**
 * 常用函数封装
 *
 * @author  hxd
 * @time    2016-04-07
 */

date_default_timezone_set('PRC');

/**
 * 获取任一长度随机字符串
 *
 * @param   int $length 字符串长度
 *
 * @return  string  $str    返回字符串
 */
function getSalt($length) {
    $str = 'abcdefghijklmnopqistuvwxyz0123456789!@#$%^&*';
    $str = str_shuffle($str);
    $rand = rand(0, strlen($str) - $length);
    $str = substr($str, $rand, $length);
    
    return $str;
}

/**
 * IsMobile函数:检测参数的值是否为正确的中国手机号码格式
 * 返回值:是正确的手机号码返回手机号码,不是返回false
 *
 * @param   string $phone 手机号码
 *
 * @return  mixed  false/mobile
 */
if (!function_exists("validPhone")) {
    function validPhone($phone) {
        if (strlen($phone) != 11) {
            return FALSE;
        }
        
        return preg_match("/^(13[0-9]{1}|15[0-9]{1}|18[0-9]{1}|14[0-9]{1}|17[0-9]{1})[0-9]{8}$/", $phone);
    }
}

/**
 * is_num函数:检测参数是否是纯数字
 *
 * @param   string $string 被检测字符串
 *
 * @return  boolean TRUE/FALSE
 */
if (!function_exists("isNum")) {
    function isNum($string) {
        return preg_match('/^[0-9]*$/', $string) ? TRUE : FALSE;
    }
}

/**
 * validStrIsStrAndNum验证字符串是否由n-n+x个字母和数字组成(不区分大小写)
 *
 * @param    string $string 被检测字符串
 *
 * @return    bool    TRUE/FALSE
 */
if (!function_exists('validStrIsStrAndNum')) {
    function validStrIsStrAndNum($string, $min, $max) {
        return preg_match('/^[a-z\d]{' . $min . ',' . $max . '}$/i', $string) ? TRUE : FALSE;
    }
}

/**
 * is_qq函数:检测参数的值是否符合QQ号码的格式
 * 返回值:是正确的QQ号码返回QQ号码,不是返回false
 *
 * @param   string $qq 被检测字符串
 *
 * @return  mixed   $qq/false   返回qq号码或者false
 */
if (!function_exists("isQq")) {
    function isQq($qq) {
        $RegExp = '/^[1-9][0-9]{5,16}$/';
        
        return preg_match($RegExp, $qq) ? $qq : FALSE;
    }
}

/**
 * 获取客户端的IP地址
 *
 * @return  string  $ip 返回ip地址
 */
if (!function_exists("getClientIp")) {
    function getClientIp() {
        $ks = array(
            "HTTP_X_FORWARDED_FOR",
            "HTTP_CLIENT_IP",
            "REMOTE_ADDR",
        );
        $kc = count($ks);
        for ($i = 0; $i < $kc; $i++) {
            $k = $ks[$i];
            $ip = trim(isset($_SERVER[$k]) ? $_SERVER[$k] : getenv($k));
            if (empty($ip) || strcasecmp($ip, "unknown") == 0) {
                continue;
            }
            $ips = explode(",", $ip);
            $ip = trim($ips[0]);
            
            if (filter_var($ip,FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        
        return '0.0.0.0';
    }
}

/**
 * 安全过滤数据
 *
 * @param   string  $str        需要处理的字符
 * @param   string  $type       返回的字符类型，支持，string,int,float,html
 * @param   maxid   $default    当出现错误或无数据时默认返回值
 * @param   boolean $checkempty 强制转化为正数
 *
 * @return  mixed               当出现错误或无数据时默认返回值
 */
if (!function_exists("getParam")) {
    function getParam($str, $type = 'string', $default = NULL, $checkempty = FALSE, $pnumber = FALSE) {
        
        switch ($type) {
            case 'string': //字符处理
                $_str = strip_tags($str);
                $_str = str_replace("'", '&#39;', $_str);
                $_str = str_replace("\"", '&quot;', $_str);
                $_str = str_replace("\\", '', $_str);
                $_str = str_replace("\/", '', $_str);
                
                $_str = daddslashes(html_escape($_str));
                
                break;
            case 'int': //获取整形数据
                $_str = verify_id($str);
                break;
            case 'float': //获浮点形数据
                $_str = (float)$str;
                break;
            case 'html': //获取HTML，防止XSS攻击
                $_str = reMoveXss($str);
                break;
            case 'time':
                $_str = $str ? strtotime($str) : '';
                break;
            default: //默认当做字符处理
                $_str = strip_tags($str);
                break;
        }
        if ($checkempty == TRUE) {
            if (empty($str)) {
                header("content-type:text/html;charset=utf-8;");
                exit("非法操作！");
            }
        }
        
        if (($type == 'string' && empty($str)) || (empty($str) && $str != 0) || !isset($str)) {
            return $default;
        }
        if ($type == "int" || $type == "float") {
            $_str = $pnumber == TRUE ? abs($_str) : $_str;
            
            return $_str;
        }
        
        return trim($_str);
    }
}

//过滤XSS攻击
if (!function_exists("reMoveXss")) {
    function reMoveXss($val) {
        $val = preg_replace('/([\x00-\x08|\x0b-\x0c|\x0e-\x19])/', '', $val);
        $search = 'abcdefghijklmnopqrstuvwxyz';
        $search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $search .= '1234567890!@#$%^&*()';
        $search .= '~`";:?+/={}[]-_|\'\\';
        for ($i = 0; $i < strlen($search); $i++) {
            $val = preg_replace('/(&#[xX]0{0,8}' . dechex(ord($search[$i])) . ';?)/i', $search[$i], $val); // with a ;
            $val = preg_replace('/(&#0{0,8}' . ord($search[$i]) . ';?)/', $search[$i], $val); // with a ;
        }
        $ra1 = Array(
            'javascript',
            'vbscript',
            'expression',
            'applet',
            'meta',
            'xml',
            'blink',
            'link',
            '<script',
            'object',
            'iframe',
            'frame',
            'frameset',
            'ilayer'
            /* , 'layer' */,
            'bgsound',
            'base',
        );
        $ra2 = Array(
            'onabort',
            'onactivate',
            'onafterprint',
            'onafterupdate',
            'onbeforeactivate',
            'onbeforecopy',
            'onbeforecut',
            'onbeforedeactivate',
            'onbeforeeditfocus',
            'onbeforepaste',
            'onbeforeprint',
            'onbeforeunload',
            'onbeforeupdate',
            'onblur',
            'onbounce',
            'oncellchange',
            'onchange',
            'onclick',
            'oncontextmenu',
            'oncontrolselect',
            'oncopy',
            'oncut',
            'ondataavailable',
            'ondatasetchanged',
            'ondatasetcomplete',
            'ondblclick',
            'ondeactivate',
            'ondrag',
            'ondragend',
            'ondragenter',
            'ondragleave',
            'ondragover',
            'ondragstart',
            'ondrop',
            'onerror',
            'onerrorupdate',
            'onfilterchange',
            'onfinish',
            'onfocus',
            'onfocusin',
            'onfocusout',
            'onhelp',
            'onkeydown',
            'onkeypress',
            'onkeyup',
            'onlayoutcomplete',
            'onload',
            'onlosecapture',
            'onmousedown',
            'onmouseenter',
            'onmouseleave',
            'onmousemove',
            'onmouseout',
            'onmouseover',
            'onmouseup',
            'onmousewheel',
            'onmove',
            'onmoveend',
            'onmovestart',
            'onpaste',
            'onpropertychange',
            'onreadystatechange',
            'onreset',
            'onresize',
            'onresizeend',
            'onresizestart',
            'onrowenter',
            'onrowexit',
            'onrowsdelete',
            'onrowsinserted',
            'onscroll',
            'onselect',
            'onselectionchange',
            'onselectstart',
            'onstart',
            'onstop',
            'onsubmit',
            'onunload',
        );
        $ra = array_merge($ra1, $ra2);
        
        $found = TRUE; // keep replacing as long as the previous round replaced something
        while ($found == TRUE) {
            $val_before = $val;
            for ($i = 0; $i < sizeof($ra); $i++) {
                $pattern = '/';
                for ($j = 0; $j < strlen($ra[$i]); $j++) {
                    if ($j > 0) {
                        $pattern .= '(';
                        $pattern .= '(&#[xX]0{0,8}([9ab]);)';
                        $pattern .= '|';
                        $pattern .= '|(&#0{0,8}([9|10|13]);)';
                        $pattern .= ')*';
                    }
                    $pattern .= $ra[$i][$j];
                }
                $pattern .= '/i';
                $replacement = substr($ra[$i], 0, 2) . '<x>' . substr($ra[$i], 2); // add in <> to nerf the tag
                $val = preg_replace($pattern, $replacement, $val); // filter out the hex tags
                if ($val_before == $val) {
                    $found = FALSE;
                }
            }
        }
        
        return $val;
    }
}


/**
 * 处理form 提交的参数过滤
 *
 * @param   string /array    $string 需要处理的字符串或者数组
 *                 $force   boolen          $force  是否强制进行处理
 *
 * @return  string/array            返回处理之后的字符串或者数组
 */
if (!function_exists("daddslashes")) {
    function daddslashes($string, $force = TRUE) {
        if (is_array($string)) {
            $keys = array_keys($string);
            foreach ($keys as $key) {
                $val = $string[$key];
                unset($string[$key]);
                $string[addslashes($key)] = daddslashes($val, $force);
            }
        } else {
            $string = addslashes($string);
        }
        
        return $string;
    }
}


/**
 * 检测提交的值是不是含有SQL注射的字符，防止注射，保护服务器安全
 *
 * @param   string $sql_str 提交的变量
 *
 * @return  boolean             返回检测结果，ture or false
 */
if (!function_exists("filterInject")) {
    function filterInject($sql_str) {
        return @preg_match('select|insert|and|or|update|delete|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile', $sql_str); // 进行过滤
    }
}

/**
 * 处理禁用HTML但允许换行的内容
 *
 * @param   string $msg 需要过滤的内容
 *
 * @return  string          返回过滤后的字符串
 */
if (!function_exists('TrimMsg')) {
    function TrimMsg($msg) {
        $msg = trim(stripslashes($msg));
        $msg = nl2br(htmlspecialchars($msg));
        $msg = str_replace("  ", "&nbsp;&nbsp;", $msg);
        
        return addslashes($msg);
    }
}

/**
 * 字符串截取，支持中文和其他编码
 *
 * @param   string $str     需要转换的字符串
 * @param   string $start   开始位置
 * @param   string $length  截取长度
 * @param   string $charset 编码格式
 * @param   string $suffix  截断显示字符
 *
 * @return  string
 */
function msubstr($str, $start = 0, $length, $suffix = TRUE, $charset = "utf-8") {
    $strength = mb_strlen($str);
    if (function_exists("mb_substr")) {
        if ($suffix) {
            if ($length < $strength) {
                return mb_substr($str, $start, $length, $charset) . "...";
            } else {
                return mb_substr($str, $start, $length, $charset);
            }
        } else {
            return mb_substr($str, $start, $length, $charset);
        }
    } elseif (function_exists('iconv_substr')) {
        if ($suffix) {//是否加上......符号
            if ($length < $strength) {
                return iconv_substr($str, $start, $length, $charset) . "...";
            } else {
                return iconv_substr($str, $start, $length, $charset);
            }
        } else {
            return iconv_substr($str, $start, $length, $charset);
        }
    }
    
    $re['utf-8'] = "/[\x01-\x7f]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xff][\x80-\xbf]{3}/";
    $re['gb2312'] = "/[\x01-\x7f]|[\xb0-\xf7][\xa0-\xfe]/";
    $re['gbk'] = "/[\x01-\x7f]|[\x81-\xfe][\x40-\xfe]/";
    $re['big5'] = "/[\x01-\x7f]|[\x81-\xfe]([\x40-\x7e]|\xa1-\xfe])/";
    preg_match_all($re[$charset], $str, $match);
    $slice = join("", array_slice($match[0], $start, $length));
    if ($suffix) {
        return $slice . "...";
    } else {
        return $slice;
    }
}

/**
 * 返回字符串长度
 *
 * @param   string $str     需要计算的字符串
 * @param   string $charset 字符编码
 *
 * @return  length  int
 */

function abslength($str, $charset = 'utf-8') {
    if (empty($str)) {
        return 0;
    }
    if (function_exists('mb_strlen')) {
        return mb_strlen($str, 'utf-8');
    } else {
        @preg_match_all("/./u", $str, $ar);
        
        return count($ar[0]);
    }
}

/**
 * 计算密码强度
 *
 * @param   string $password 被检测字符串
 *
 * @return  int     $level      安全等级
 */
if (!function_exists("getPassLevel")) {
    function getPassLevel($password) {
        $partArr = array(
            '/[0-9]/',
            '/[a-z]/',
            '/[A-Z]/',
            '/[\W_]/',
        );
        $score = 0;
        
        //根据长度加分
        $score += strlen($password);
        //根据类型加分
        foreach ($partArr as $part) {
            if (preg_match($part, $password)) {
                $score += 5;
            }//某类型存在加分
            $regexCount = preg_match_all($part, $password, $out);//某类型存在，并且存在个数大于2加2份，个数大于5加7份
            if ($regexCount >= 5) {
                $score += 7;
            } elseif ($regexCount >= 2) {
                $score += 2;
            }
        }
        //重复检测
        $repeatChar = '';
        $repeatCount = 0;
        for ($i = 0; $i < strlen($password); $i++) {
            if ($password{$i} == $repeatChar) {
                $repeatCount++;
            } else {
                $repeatChar = $password{$i};
            }
        }
        $score -= $repeatCount * 2;
        //等级输出
        $level = 0;
        if ($score <= 10) { //弱
            $level = 1;
        } elseif ($score <= 25) { //一般
            $level = 2;
        } elseif ($score <= 37) { //很好
            $level = 3;
        } elseif ($score <= 50) { //极佳
            $level = 4;
        } else {
            $level = 4;
        }
        //如果是密码为123456
        if (in_array($password, array(
            '123456',
            'abcdef',
        ))) {
            $level = 1;
        }
        
        return $level;
    }
}

/**
 * 获取订单号
 *
 * @return  string  返回订单号
 */
if (!function_exists('get_order_sn')) {
    function get_order_sn() {
        /* 选择一个随机的方案 */
        mt_srand((double)microtime() * 1000000);
        
        return date('YmdHis') . str_pad(mt_rand(1, 999999), 6, '0', STR_PAD_LEFT);
    }
}

/**
 * JSON输出
 *
 * @param   array $data 数组
 *
 * @return  string          json字符串
 */
if (!function_exists("printJson")) {
    function printJson($data) {
        $jcb = getParam(isset($_REQUEST['jsoncallback']) ? $_REQUEST['jsoncallback'] : '');
        if ($jcb) {//如果是跨域操作
            echo $jcb . "(" . json_encode($data, JSON_UNESCAPED_UNICODE) . ");";
        } else {
            //var_dump(is_object(json_encode($data)));
            exit(json_encode($data, JSON_UNESCAPED_UNICODE));    //中文不转码
        }
        exit();
    }
}

/**
 * 发送http请求
 *
 * @return string
 */
function sendHttp($url, $data = array(), $post = TRUE, $httpHeader = array(), $cookieFile = '/tmp/mycookiefile') {
    if (is_array($data)) {
        $data = http_build_query($data);
    }
    if (!$post) {
        $url .= '?' . $data;
    }
    $options = array(
        CURLOPT_URL            => $url,
        CURLOPT_HEADER         => FALSE,
        CURLOPT_RETURNTRANSFER => TRUE,
        CURLOPT_USERAGENT      => 'CURL ' . date('Y-m-d H:i:s'),
        CURLOPT_FOLLOWLOCATION => TRUE,
        CURLOPT_TIMEOUT        => 10,
    );
    if ($post) {
        $options[CURLOPT_POST] = TRUE;
        $options[CURLOPT_POSTFIELDS] = $data;
    }
    if ($cookieFile) {
        $options[CURLOPT_COOKIEFILE] = $cookieFile;
        $options[CURLOPT_COOKIEJAR] = $cookieFile;
    }
    if ($httpHeader) {
        $options[CURLOPT_HTTPHEADER] = $httpHeader;
    }
    $ch = curl_init();
    curl_setopt_array($ch, $options);
    $info = curl_exec($ch);
    curl_close($ch);
    
    return $info;
}

/**
 * 获取随机数
 *
 * @param        $length 随记数长度
 * @param string $chars  随机字符串
 *
 * @return string 返回生成的随机数
 */
function random($length, $chars = '0123456789') {
    $hash = '';
    $max = strlen($chars) - 1;
    for ($i = 0; $i < $length; $i++) {
        $hash .= $chars[mt_rand(0, $max)];
    }
    
    return $hash;
}


//排序二维数组，指定字段排列
function sortArray($source, $filed, $sort = 'desc') {
    
    $arr = array();
    foreach ($source as $key => $value) {
        $arr[$key] = $value[$filed];
    }
    
    array_multisort($arr, $sort == 'desc' ? SORT_DESC : SORT_ASC, $source);
    
    return $source;
}

/**
 * 字符串查找，是否包含
 *
 * @param   string $str  被检测字符串
 * @param   string $find 查找字符串
 *
 * @return  bool    TRUE/FALS   是否
 */

function isContain($str, $find) {
    if (empty($find)) {
        return TRUE;
    }
    
    $pos = strpos($str, $find);
    if ($pos === FALSE) {
        return FALSE;
    } else {
        return TRUE;
    }
}


/**
 * 返回当前页面的URL
 */
function getPageUrl() {
    
    $pageURL = 'http';
    if (isset($_SERVER["HTTPS"]) ? $_SERVER["HTTPS"] : '' == "on") {
        $pageURL .= "s";
    }
    $pageURL .= "://";
    
    if ($_SERVER["SERVER_PORT"] != "80") {
        $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
    } else {
        $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
    }
    
    return $pageURL;
}

/**
 * json返回结果
 *
 * @param   string $code 状态码
 * @param   string $msg  返回信息
 * @param   array  $data 返回数据
 */
function PJsonMsg($code, $msg, $data = array()) {
    $result = array(
        'header' => array(
            'code' => (string)$code,
            'msg'  => $msg,
        ),
        'body'   => $data,
    );
    printJson($result);
}

/**
 * 使用openssl库进行加密
 *
 * @param  string $string 要加密字符串
 * @param  string $key    加密key
 *
 * @return string   $string 加密后的字符串
 */
function opensslEncrypt($string, $key, $method = 'AES-256-ECB') {
    $str = openssl_encrypt($string, $method, $key);
    
    return $str;
}

/**
 * 使用openssl库进行解密
 *
 * @param  string $string 要解密字符串
 * @param  string $key    解密key
 *
 * @return string   $string 解密后的字符串
 */
function opensslDecrypt($string, $key, $method = 'AES-256-ECB') {
    $str = openssl_decrypt($string, $method, $key);
    
    return $str;
}

//任意字符编码转换为UTF-8
function getUtf8($string) {
    $encode = mb_detect_encoding($string);
    $string = iconv($encode, "UTF-8", $string);
    
    return $string;
}

//生成验证码
function verifyCode($width = 100, $height = 35) {
    //随机生成的字符串
    $str = rand_str(4);
    $_SESSION['code_login'] = md5($str);
    $fontface = "./assets/fonts/t1.ttf";
    
    //声明需要创建的图层的图片格式
    @ header("Content-Type:image/png");
    //创建一个图层
    $im = imagecreatetruecolor($width, $height);
    //背景色
    $back = imagecolorallocate($im, 255, 255, 255);
    //模糊点颜色
    $pix = imagecolorallocate($im, 250, 250, 250);
    imagefill($im, 0, 0, $pix);
    //绘模糊作用的点
    for ($i = 0; $i < 1000; $i++) {
        imagesetpixel($im, mt_rand(0, $width), mt_rand(0, $height), $pix);
    }
    //添加干扰线
    for ($i = 0; $i < 15; $i++) {
        $fontcolor = imagecolorallocate($im, mt_rand(0, 255), mt_rand(0, 255), mt_rand(0, 255));
        imagearc($im, mt_rand(-10, $width), mt_rand(-10, $height), mt_rand(30, 300), mt_rand(20, 200), 55, 44, $fontcolor);
    }
    for ($i = 0; $i < 255; $i++) {
        $fontcolor = imagecolorallocate($im, mt_rand(0, 255), mt_rand(0, 255), mt_rand(0, 255));
        imagesetpixel($im, mt_rand(0, $width), mt_rand(0, $height), $fontcolor);
    }
    //随机字符位置
    for ($i = 0; $i <= 3; $i++) {
        $fontcolor = imagecolorallocate($im, mt_rand(0, 120), mt_rand(0, 120), mt_rand(0, 120));
        imagettftext($im, ($height - 2) / 2, rand(-$height, $height), (($width - 5) / 5) * $i + (($width - 10) / 8), rand($height * 3 / 5, ($height * 3 / 5 + 5)), $fontcolor, $fontface, $str[$i]);
    }
    
    //输出图片
    imagepng($im);
    
    imagedestroy($im);
    
    
}

//导出excel
function getExcel($title, $data) {
    header("Content-type:application/vnd.ms-excel");
    header("Content-Disposition:filename=xls_region.xls");
    
    echo "<table border='1'><tr>";
    //导出表头
    foreach ($title as $value) {
        echo "<th>" . $value . "</th>";
    }
    echo "</tr>";
    
    //导出数据
    foreach ($data as $v) {
        echo "<tr>";
        foreach ($title as $k => $vv) {
            echo "<td>" . $v[$k] . "</td>";
        }
        echo "</tr>";
    }
    echo "</table>";
}

/**
 * 发送电子邮件
 *
 * @param   string $to      收件人
 * @param   string $subject 标题
 * @param   string $message 内容
 */
function sendEmail($to, $subject, $message) {
    $ci = &get_instance();
    $ci->load->library('email'); //加载类库
    
    //以下设置Email参数
    $config = config_item('email');
    $ci->email->initialize($config);
    //以下设置Email内容
    $ci->email->from($config['from']);
    $ci->email->to($to);
    $ci->email->subject($subject);
    $ci->email->message($message);
    
    $result = $ci->email->send();
    if ($result) {
        return TRUE;
    } else {
        return FALSE;
    }
}

//数组转xml格式
class arrayToXml {
    private $version = '1.0';
    private $encoding = 'UTF-8';
    private $root = 'root';
    private $xml = NULL;
    
    function __construct() {
        $this->xml = new XMLWriter();
    }
    
    function toXml($data, $isArray = FALSE) {
        if (!$isArray) {
            $this->xml->openMemory();
            $this->xml->startDocument($this->version, $this->encoding);
            $this->xml->startElement($this->root);
        }
        
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $this->xml->startElement($key);
                $this->toXml($value, TRUE);
                $this->xml->endElement();
                        continue;
            }
            $this->xml->writeElement($key, $value);
        }
        if (!$isArray) {
            $this->xml->endElement();
            
            return $this->xml->outputMemory(TRUE);
        }
    }
    
    function toArray($string) {
        $arr = new SimpleXMLElement($string);
        
        return $arr;
    }
}

//匹配0.01到999.99数字
function matchNum($num) {
    $pattern = '/^(?!0$)([1-9][0-9]{0,2}|0)(\.(?![0]{1,2}$)[0-9]{1,2})?$/';
    
    return preg_match($pattern, $num);
}

//获取请求来源域名
function requestSource() {
    $url = $_SERVER["HTTP_REFERER"];   //获取完整的来路URL
    $str = str_replace("http://", "", $url);  //去掉http://
    $strdomain = explode("/", $str);           // 以“/”分开成数组
    $domain = $strdomain[0];        //取第一个“/”以前的字符
    
    return $domain;
}

/**
 * 预约防刷
 *
 * @param   string $key      key
 * @param   int    $interval 间隔秒数
 *
 * @return  string
 */
function preventBrush($key, $interval) {
    $brush_key = $key . ip2long(get_client_ip());
    $now = time();
    if (isset($_SESSION[$brush_key]) && ($now - $_SESSION[$brush_key] < 0)) {
        PJsonMsg(REQUEST_ERROR, lang('server_busy'));
    } else {
        $_SESSION[$brush_key] = $now + $interval;
    }
}

//获取浏览器支持语言
function getLanguage() {
    $lang = empty($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? 'zh-C' : substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 4);
    if (preg_match("/zh-c/i", $lang)) {
        $lang = 1;
    } else if (preg_match("/zh/i", $lang)) {
        $lang = 2;
    } else if (preg_match("/en/i", $lang)) {
        $lang = 3;
    } else if (preg_match("/jp/i", $lang)) {
        $lang = 4;
    }
    
    return $lang;
}


/**
 *  不加千分位逗号的数字格式化
 *
 * @param        $number        要格式化的数字
 * @param int    $decimals      小数位数
 * @param string $dec_point     小数点
 * @param string $thousands_sep 千分位符号
 *
 * @return string
 */
function _numberFormat($number, $decimals = 0, $dec_point = '.', $thousands_sep = '') {
    return number_format($number, $decimals, $dec_point, $thousands_sep);
    
}

/**
 * 时间格式化
 *
 * @param $time     int     时间戳
 * @param $format   string  时间格式:默认 Y-m-d H:i:s
 * @param $format   int     间隔
 *
 * @return false|string
 */
function formatDate($time, $format = 'Y/m/d H:i', $offset = 60) {
    $rtime = date($format, $time);
    $time = time() - $time;
    
    if ($time < $offset) {
        $str = '刚刚';
    } elseif ($time < 60 * 60) {
        $min = floor($time / 60);
        $str = $min . '分钟前';
    } elseif ($time < 60 * 60 * 24) {
        $h = floor($time / (60 * 60));
        $str = $h . '小时前';
    } elseif ($time < 60 * 60 * 24 * 30) {
        $d = floor($time / (60 * 60 * 24));
        $str = $d . '天前';
    } else {
        $str = $rtime;
    }
    
    return $str;
}

//二维数组排序
if (!function_exists('array_sort_by')) {
    function array_sort_by($list, $field, $sortby = 'asc') {
        if (is_array($list)) {
            $refer = $resultSet = array();
            foreach ($list as $i => $data) {
                $refer[$i] = &$data[$field];
            }
            switch ($sortby) {
                case 'asc': // 正向排序
                    asort($refer);
                    break;
                case 'desc': // 逆向排序
                    arsort($refer);
                    break;
                case 'nat': // 自然排序
                    natcasesort($refer);
                    break;
            }
            foreach ($refer as $key => $val) {
                $resultSet[] = &$list[$key];
            }
            
            return $resultSet;
        }
        
        return FALSE;
    }
}
/**
 * 访问客户端类型
 *
 * @return bool
 */
function getClientInfo() {
    // 如果有HTTP_X_WAP_PROFILE则一定是移动设备
    if (isset ($_SERVER['HTTP_X_WAP_PROFILE'])) {
        return TRUE;
    }
    // 如果via信息含有wap则一定是移动设备,部分服务商会屏蔽该信息
    if (isset ($_SERVER['HTTP_VIA'])) {
        // 找不到为flase,否则为true
        return stristr($_SERVER['HTTP_VIA'], "wap") ? TRUE : FALSE;
    }
    // 脑残法，判断手机发送的客户端标志,兼容性有待提高
    if (isset ($_SERVER['HTTP_USER_AGENT'])) {
        $clientkeywords = array('nokia', 'sony',
            'ericsson',
            'mot',
            'samsung',
            'htc',
            'sgh',
            'lg',
            'sharp',
            'sie-',
            'philips',
            'panasonic',
            'alcatel',
            'lenovo',
            'iphone',
            'ipod',
            'blackberry',
            'meizu',
            'android',
            'netfront',
            'symbian',
            'ucweb',
            'windowsce',
            'palm',
            'operamini',
            'operamobi',
            'openwave',
            'nexusone',
            'cldc',
            'midp',
            'wap',
            'mobile',
        );
        
        // 从HTTP_USER_AGENT中查找手机浏览器的关键字
        if (preg_match("/(" . implode('|', $clientkeywords) . ")/i", strtolower($_SERVER['HTTP_USER_AGENT']))) {
            return TRUE;
        }
    }
    // 协议法，因为有可能不准确，放到最后判断
    if (isset ($_SERVER['HTTP_ACCEPT'])) {
        // 如果只支持wml并且不支持html那一定是移动设备
        // 如果支持wml和html但是wml在html之前则是移动设备
        if ((strpos($_SERVER['HTTP_ACCEPT'], 'vnd.wap.wml') !== FALSE) && (strpos($_SERVER['HTTP_ACCEPT'], 'text/html') === FALSE || (strpos($_SERVER['HTTP_ACCEPT'], 'vnd.wap.wml') < strpos($_SERVER['HTTP_ACCEPT'], 'text/html')))) {
            return TRUE;
        }
    }
    
    return FALSE;
}

//获取文章内容里的图片url
function getImgUrl($content) {
    $pattern = '<img.*?src="(.*?)">';
    preg_match($pattern, $content, $match);
    
    return $match;
}

//验证身份证号
function isIdcard($id) {
    $id = strtoupper($id);
    $regx = "/(^\d{15}$)|(^\d{17}([0-9]|X)$)/";
    $arr_split = array();
    if (!preg_match($regx, $id)) {
        return FALSE;
    }
    //检查15位
    if (15 == strlen($id)) {
        $regx = "/^(\d{6})+(\d{2})+(\d{2})+(\d{2})+(\d{3})$/";
        
        @preg_match($regx, $id, $arr_split);
        //检查生日日期是否正确
        $dtm_birth = "19" . $arr_split[2] . '/' . $arr_split[3] . '/' . $arr_split[4];
        if (!strtotime($dtm_birth)) {
            return FALSE;
        } else {
            return TRUE;
        }
    } else {//检查18位
        $regx = "/^(\d{6})+(\d{4})+(\d{2})+(\d{2})+(\d{3})([0-9]|X)$/";
        @preg_match($regx, $id, $arr_split);
        $dtm_birth = $arr_split[2] . '/' . $arr_split[3] . '/' . $arr_split[4];
        if (!strtotime($dtm_birth))  //检查生日日期是否正确
        {
            return FALSE;
        } else {
            //检验18位身份证的校验码是否正确。
            //校验位按照ISO 7064:1983.MOD 11-2的规定生成，X可以认为是数字10。
            $arr_int = array(7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2);
            $arr_ch = array('1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2');
            $sign = 0;
            for ($i = 0; $i < 17; $i++) {
                $b = (int)$id{$i};
                $w = $arr_int[$i];
                $sign += $b * $w;
            }
            $n = $sign % 11;
            $val_num = $arr_ch[$n];
            if ($val_num != substr($id, 17, 1)) {
                return FALSE;
            } else {
                return TRUE;
            }
        }
    }
    
}

//验证中文名字
function isChineseName($name) {
    if (preg_match('/^([\xe4-\xe9][\x80-\xbf]{2}){2,}$/', $name)) {
        return TRUE;
    } else {
        return FALSE;
    }
}