<?php
/**
 * IPTrust Plugin II
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * original @author     Andriy Lesyuk <andriy.lesyuk@softjourn.com>
 * modified by Gero Gothe <gero.gothe@medizindoku.de>
 * 
 */

if(!defined('DOKU_INC')) die();
if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');

require_once(DOKU_PLUGIN.'action.php');

class action_plugin_iptrust2 extends DokuWiki_Action_Plugin {

    /**
     * Register event handlers
     */
    function register(Doku_Event_Handler $controller) {
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_act_preprocess', array());
    }

    /**
     * Check if content should be shown
     */
    function handle_act_preprocess(&$event, $param) {
        global $conf;
        if (!isset($_SERVER['REMOTE_USER'])) {
            if (!in_array($event->data, array('login', 'register', 'resendpwd'))) {
                $ip = clientIP(true);
                $ips = @file(DOKU_CONF.'iptrust.conf', FILE_SKIP_EMPTY_LINES);
                if (!$ips || !in_array($ip."\n", $ips)) {
                    $event->data = 'login';
                }
            }
        } else {
            if ($event->data == 'login') {
                $nets = $this->getConf('log_networks');
                if ($nets) {
                    $ip = clientIP(true);
                    $ips = @file(DOKU_CONF.'iptrust.conf', FILE_SKIP_EMPTY_LINES);
                    if (!$ips || !in_array($ip."\n", $ips)) {
                        $nets = preg_split('/, */', $nets);
                        foreach ($nets as $net) {
                            if (strpos($ip, $net) === 0) {
                                $i = 0;
                                $logins = @file($conf['cachedir'].'/iptrust', FILE_SKIP_EMPTY_LINES);
                                if ($logins) {
                                    for ($i = 0; $i < sizeof($logins); $i++) {
                                        list($login, $host, $date) = explode("\t", $logins[$i]);
                                        if ($ip == $host) {
                                            break;
                                        }
                                    }
                                } else {
                                    $logins = array();
                                }
                                $logins[$i] = $_SERVER['REMOTE_USER']."\t".$ip."\t".time()."\n";
                                io_saveFile($conf['cachedir'].'/iptrust', join('', $logins));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

}
