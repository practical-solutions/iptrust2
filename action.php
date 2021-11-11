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
        $controller->register_hook('AUTH_ACL_CHECK', 'AFTER', $this, 'ip_group', array());
        
    }


    function ip_group(&$event, $param) {
        $ip = clientIP(true);
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
                    
                    # Allow access, if allowed for the group @publicaccess
                    global $ID;
                    $perms = $this->aclcheck($ID);
                    
                    
                    if (!$perms['@publicaccess'] == 1) $event->data = 'login';
                    
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


    /** This function is from the aclinfo-plug by Andreas Gohr
     * Version 2020-10-01
     * https://www.dokuwiki.org/plugin:aclinfo
     */
    function aclcheck($id){
        global $conf;
        global $AUTH_ACL;

        $id    = cleanID($id);
        $ns    = getNS($id);
        $perms = array();

        //check exact match first
        $matches = preg_grep('/^'.preg_quote($id,'/').'\s+/',$AUTH_ACL);
        if(count($matches)){
            foreach($matches as $match){
                $match = preg_replace('/#.*$/','',$match); //ignore comments
                $acl   = preg_split('/\s+/',$match);
                if($acl[2] > AUTH_DELETE) $acl[2] = AUTH_DELETE; //no admins in the ACL!
                if(!isset($perms[$acl[1]])) $perms[$acl[1]] = $acl[2];
            }
        }

        //still here? do the namespace checks
        if($ns){
            $path = $ns.':\*';
        }else{
            $path = '\*'; //root document
        }

        do{
            $matches = preg_grep('/^'.$path.'\s+/',$AUTH_ACL);
            if(count($matches)){
                foreach($matches as $match){
                    $match = preg_replace('/#.*$/','',$match); //ignore comments
                    $acl   = preg_split('/\s+/',$match);
                    if($acl[2] > AUTH_DELETE) $acl[2] = AUTH_DELETE; //no admins in the ACL!
                    if(!isset($perms[$acl[1]])) $perms[$acl[1]] = $acl[2];
                }
            }

            //get next higher namespace
            $ns   = getNS($ns);

            if($path != '\*'){
                $path = $ns.':\*';
                if($path == ':\*') $path = '\*';
            }else{
                //we did this already
                //break here
                break;
            }
        }while(1); //this should never loop endless

        return $perms;
    }

}
