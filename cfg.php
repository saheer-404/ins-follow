<?php
date_default_timezone_set('Asia/Kolkata');


function saveData($saveFile, $data){
    $x = $data . "\n";
    $y = fopen($saveFile, 'a');
    fwrite($y, $x);
    fclose($y);
}
function saveCookie($saveFile, $data){
    $x = $data;
    $y = fopen($saveFile, 'w');
    fwrite($y, $x);
    fclose($y);
}

function read ($length='255')
{
    if (!isset ($GLOBALS['StdinPointer']))
    {
        $GLOBALS['StdinPointer'] = fopen ("php://stdin","r");
    }
    $line = fgets ($GLOBALS['StdinPointer'],$length);
    return trim ($line);
}

function request($ighost, $useragent, $url, $cookie = 0, $data = 0, $httpheader = array(), $proxy = 0, $userpwd = 0, $is_socks5 = 0)
{
    $url = $ighost ? 'https://i.instagram.com/api/v1/' . $url : $url;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    if ($proxy) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }

    if ($userpwd) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $userpwd);
    }

    if ($is_socks5) {
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    }

    if ($httpheader) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheader);
    }

    curl_setopt($ch, CURLOPT_HEADER, 1);
    if ($cookie) {
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }

    if ($data):
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    endif;
    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch);
    if (!$httpcode) {
        return false;
    } else {
        $header = substr($response, 0, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
        $body = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
        curl_close($ch);
        return array($header, $body);
    }
}

function generateDeviceId($seed=0)
{
    $volatile_seed = filemtime(__DIR__);
    return 'android-' . substr(md5($seed . $volatile_seed), 16);
}
function generateSignature($data)
{
    $hash = hash_hmac('sha256', $data, '109513c04303341a7daf27bb41b268e633b30dcc65a3fe14503f743176113869');
    return 'ig_sig_key_version=4&signed_body=' . $hash . '.' . urlencode($data);
}
function generate_useragent()
{
    return 'Instagram 10.8.0 Android (18/4.3; 320dpi; 720x1280; Xiaomi; HM 1SW; armani; qcom; en_US';
}
function get_csrftoken()
{
    $fetch = request('si/fetch_headers/', null, null);
    $header = $fetch[0];
    if (!preg_match('#ookie: csrftoken=([^;]+)#', $fetch[0], $token)) {
        return json_encode(array('result' => false, 'content' => 'Missing csrftoken'));
    } else {
        return substr($token[0], 22);
    }
}
function generateUUID($type=0)
{
    $uuid = sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff)
    );

    return $type ? $uuid : str_replace('+', '', $uuid);
}
function instagram_login($post_password)
{
    preg_match_all('/access\_token\=(.*?)\&/', $post_password, $token);
    $post_password = $token[1][0];
    $postq = json_encode([
        'phone_id' => generateUUID(true),
        '_csrftoken' => get_csrftoken(),
        'guid' => generateUUID(true),
        'device_id' => generateUUID(true),
        'fb_access_token' => $post_password,
        'login_attempt_count' => 0,
    ]);
    $a = request(1, generate_useragent(), 'fb/facebook_signup/', 0, generateSignature($postq));
    $header = $a[0];
    $a = json_decode($a[1]);
    if ($a->status == 'ok') {
        preg_match_all('%ookie: (.*?);%', $header, $d);
        $cookies = '';
        for ($o = 0; $o < count($d[0]); $o++) {
            $cookies .= $d[1][$o] . ";";
        }

        $id = $a->logged_in_user->pk;
        $usern = $a->logged_in_user->username;
        $array = json_encode(['status' => true, 'cookies' => $cookies, 'useragent' => generate_useragent(), 'id' => $id, 'user' => $usern]);
    } else {
        $array = json_encode(['status' => false, 'msg' => 'Invalid user/pass or verify']);
    }
    return $array;
}
function rando($length) {
  $characters = '1234567890abcdefghijklmnopqrstuvwxyz';

  $charactersLength = strlen($characters);
  $randomString = '';
  for ($i = 0; $i < $length; $i++) {
      $randomString .= $characters[rand(0, $charactersLength - 1)];
  }
  return $randomString;
}
function randozz($length) {
  $characters = 'abcdefghijklABCDEFGHIJKLMNOPQRSTUVWXYZmnopqrstuvwxyz';

  $charactersLength = strlen($characters);
  $randomString = '';
  for ($i = 0; $i < $length; $i++) {
      $randomString .= $characters[rand(0, $charactersLength - 1)];
  }
  return $randomString;
}
function RandomNumber($length){
$str="";
for($i=0;$i<$length;$i++){
$str.=mt_rand(0,9);
}
return $str;
}
function instagram_logins($post_username, $post_password)
{
    $postq = json_encode([
        'phone_id' => generateUUID(true),
        '_csrftoken' => get_csrftoken(),
        'username' => $post_username,
        'guid' => generateUUID(true),
        'device_id' => generateUUID(true),
        'password' => $post_password,
        'login_attempt_count' => 0,
    ]);
    $ua = generate_useragent();
    $a = request(1, generate_useragent(), 'accounts/login/', 0, generateSignature($postq));
    $header = $a[0];
    $a = json_decode($a[1]);
    preg_match('#ookie: csrftoken=([^;]+)#i', $header, $token);
	$a->token = $token[1];
	$a->headers = $header;
    $a->ua = $ua;
    preg_match_all('%ookie: (.*?);%', $header, $d);
    $cookies = '';
    for ($o = 0; $o < count($d[0]); $o++) {
        $cookies .= $d[1][$o] . ";";
    }
    $a->cookies = $cookies;

    if ($a->status == 'ok') {
        preg_match_all('%ookie: (.*?);%', $header, $d);
        $cookies = '';
        for ($o = 0; $o < count($d[0]); $o++) {
            $cookies .= $d[1][$o] . ";";
        }

        $id = $a->logged_in_user->pk;
        $usern = $a->logged_in_user->username;
        $array = json_encode(['status' => true, 'cookies' => $cookies, 'useragent' => generate_useragent(), 'id' => $id, 'user' => $usern, 'device' => generateUUID(true)]);
    }else if($a->error_type == "checkpoint_challenge_required") {
        session_start();
        $_SESSION['c_cookie'] = $cookies;
        $_SESSION['c_ua'] = $ua;
        $_SESSION['c_token'] = $token[1];
        $_SESSION['c_url'] = $a->challenge->url;
        $_SESSION['c_username'] = $post_username;
        $_SESSION['c_password'] = $post_password;
        $array = json_encode(['status' => false, 'msg' => 'Cekpoint', 'error_type' => 'cekpoint', 'url' => $a->challenge->url, 'token' => $a->token, 'ua' => $a->ua, 'cookies' => $a->cookies]);
    } else {
        $array = json_encode(['status' => false, 'msg' => $a->message]);
    }
    return $array;
}
function getUserID($username)
{
	$a = request(0, 0, "https://instagram.com/$username");
	preg_match('#,"id":"(.*?)",#', $a[1], $ids);
	$id = $ids[1];
	if (!is_numeric($id)) {
		$id = null;
	}
	return $id;
}
