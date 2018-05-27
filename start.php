<?php 
use \Workerman\Worker;
use \Workerman\Connection\TcpConnection;
use \Workerman\Connection\AsyncTcpConnection;


require_once __DIR__ . '/vendor/autoload.php';

define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_AUTH', 6);
define('STAGE_DESTROYED', -1);


define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);

/*
 * login and password for auth
 */
define('USERNAME', 'username');
define('PASSWORD', 'password');

$worker = new Worker('tcp://0.0.0.0:1080');
$worker->onConnect = function(TcpConnection $connection)
{
    $connection->stage = STAGE_INIT;
};
$worker->onMessage = function(TcpConnection $connection, $buffer)
{
    switch($connection->stage)
    {
        case STAGE_INIT:

            /** @var TcpConnection $connection
             * adding auth login/passwd
             * 0x05 - socks ver.5
             * 0x01 - count of auth methods - 1 in our case
             * 0x02 - auth method by login/password
             */

            if ($buffer[0] === "\x05" && $buffer[1] >= "\x01") {
                if (strpos(substr($buffer,2), "\x02") !== false) {
                    $connection->send("\x05\x02");
                    $connection->stage = STAGE_AUTH;

                    return;
                } else {
                    $connection->stage = STAGE_DESTROYED;
                    $connection->send("\x05\xFF");

                    return;
                }

            } else {
                $connection->send("\x05\xFF");
                $connection->stage = STAGE_DESTROYED;

                return;
            }

        case STAGE_AUTH:
            if ($buffer[0] === "\x01") { // this is not SOCKS proto version: https://tools.ietf.org/html/rfc1929
                try {
                    $ulen = ord($buffer[1]);
                    $plen = ord($buffer[1 + $ulen + 1]); // ver[0] + ulen[1] + offset[ulen] + 1

                    if ($ulen >= 1 && $ulen <= 255)
                        $uname = substr($buffer, 2, $ulen);
                    if ($plen >= 1 && $plen <= 255)
                        $passwd = substr($buffer, 2 + $ulen + 1, $plen);

                    $uname = (isset($uname)) ? bin2str($uname) : '';
                    $passwd = (isset($passwd)) ? bin2str($passwd) : '';

                    if ($uname === USERNAME && $passwd === PASSWORD) {
                        $connection->send("\x01\x00"); // auth accepted
                        $connection->stage = STAGE_ADDR;

                        return;
                    } else {
                        $connection->send("\x01\xFF"); // auth denied
                        $connection->stage = STAGE_DESTROYED;
                        echo "Wrong credentials: username: $uname / password: $passwd \n";
                        return;
                    }
                } catch (Exception $e) {
                    echo 'Exception: ', $e->getMessage(), "\n";
;
                    $connection->send("\x01\xFF");
                    $connection->stage = STAGE_DESTROYED;
                    return;
                }
            }

            return;

        case STAGE_DESTROYED:
            $connection->close();
            return;

        case STAGE_ADDR:
            $cmd = ord($buffer[1]);
            if($cmd != CMD_CONNECT)
            {
               echo "bad cmd $cmd\n";
               $connection->close();
               return;
            }
            $header_data = parse_socket5_header($buffer);
            if(!$header_data)
            {
                $connection->close();
                return;
            }
            $connection->stage = STAGE_CONNECTING;
            $remote_connection = new AsyncTcpConnection('tcp://'.$header_data[1].':'.$header_data[2]);
            $remote_connection->onConnect = function(AsyncTcpConnection $remote_connection)use($connection)
            {
                $connection->state = STAGE_STREAM;
                $connection->send("\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10");
                $connection->pipe($remote_connection);
                $remote_connection->pipe($connection);
            };
            $remote_connection->connect();
    }
};


function parse_socket5_header($buffer)
{
    $addr_type = ord($buffer[3]);
    switch($addr_type)
    {
        case ADDRTYPE_IPV4:
            if(strlen($buffer) < 10)
            {
                echo bin2hex($buffer)."\n";
                echo "buffer too short\n";
                return false;
            }
            $dest_addr = ord($buffer[4]).'.'.ord($buffer[5]).'.'.ord($buffer[6]).'.'.ord($buffer[7]);
            $port_data = unpack('n', substr($buffer, -2));
            $dest_port = $port_data[1];
            $header_length = 10;
            break;
        case ADDRTYPE_HOST:
            $addrlen = ord($buffer[4]);
            if(strlen($buffer) < $addrlen + 5)
            {
                echo $buffer."\n";
                echo bin2hex($buffer)."\n";
                echo "buffer too short\n";
                return false;
            }
            $dest_addr = substr($buffer, 5, $addrlen);
            $port_data = unpack('n', substr($buffer, -2));
            $dest_port = $port_data[1];
            $header_length = $addrlen + 7;
            break;
       case ADDRTYPE_IPV6:
            if(strlen($buffer) < 22)
            {
                echo "buffer too short\n";
                return false;
            }
            echo "todo ipv6\n";
            return false;
       default:
            echo "unsupported addrtype $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length);
}

function bin2str(string $bstring) {
    $ascii_arr = unpack('C*', $bstring);
    $str = '';
    foreach ($ascii_arr as $chr) {
        $str .= chr($chr);
    }

    return $str;
}

if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
