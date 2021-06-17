<?php
/**
 * IPTrust Plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Andriy Lesyuk <andriy.lesyuk@softjourn.com>
 */

if(!defined('DOKU_INC')) die();
if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');

require_once(DOKU_PLUGIN.'admin.php');

class admin_plugin_iptrust2 extends DokuWiki_Admin_Plugin {


    /**
     * This functionality should be available only ot administrator
     */
    function forAdminOnly() {
        return false;
    }

    /**
     * Handles user request
     */
    function handle() {
        if (isset($_REQUEST['ip']) && ($_REQUEST['ip'] != '')) {
            if (preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $_REQUEST['ip']) &&
                (ip2long($_REQUEST['ip']) !== false)) {
                $ip = long2ip(ip2long($_REQUEST['ip']));
                $ips = @file(DOKU_CONF.'iptrust.conf', FILE_SKIP_EMPTY_LINES);
                if ($ips && (sizeof($ips) > 0)) {
                    if (in_array($ip."\n", $ips)) {
                        msg($this->getLang('already'), -1);
                        return;
                    }
                }
                io_saveFile(DOKU_CONF.'iptrust.conf', $ip."\n", true);
            } else {
                msg($this->getLang('invalid_ip'), -1);
            }
        } elseif (isset($_REQUEST['delete']) && is_array($_REQUEST['delete']) && (sizeof($_REQUEST['delete']) > 0)) {
            $ips = @file(DOKU_CONF.'iptrust.conf', FILE_SKIP_EMPTY_LINES);
            if ($ips && (sizeof($ips) > 0)) {
                $count = sizeof($ips);
                foreach ($_REQUEST['delete'] as $ip => $dummy) {
                    if (preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $ip) &&
                        (ip2long($ip) !== false)) {
                        $ip = long2ip(ip2long($ip));
                        $i = array_search($ip."\n", $ips);
                        if ($i !== false) {
                            array_splice($ips, $i, 1);
                        }
                    } else {
                        msg($this->getLang('invalid_ip'), -1);
                        break;
                    }
                }
                if (sizeof($ips) < $count) {
                    io_saveFile(DOKU_CONF.'iptrust.conf', join('', $ips));
                }
            } else {
                msg($this->getLang('failed'), -1);
            }
        } elseif (isset($_REQUEST['add']) && is_array($_REQUEST['add']) && (sizeof($_REQUEST['add']) > 0)) {
            $ips = @file(DOKU_CONF.'iptrust.conf', FILE_SKIP_EMPTY_LINES);
            foreach ($_REQUEST['add'] as $ip => $dummy) {
                if (preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $ip) &&
                    (ip2long($ip) !== false)) {
                    $ip = long2ip(ip2long($ip));
                    if ($ips && (sizeof($ips) > 0)) {
                        if (in_array($ip."\n", $ips)) {
                            msg($this->getLang('already'), -1);
                            return;
                        }
                    }
                    io_saveFile(DOKU_CONF.'iptrust.conf', $ip."\n", true);
                }
            }
        } elseif (isset($_REQUEST['clear'])) {
            if (file_exists($conf['cachedir'].'/iptrust')) {
                @unlink($conf['cachedir'].'/iptrust');
            }
        }
    }

    /**
     * Shows edit form
     */
    function html() {
        global $conf;

        print $this->locale_xhtml('intro');

        print $this->locale_xhtml('list');
        ptln("<div class=\"level2\">");
        ptln("<form action=\"\" method=\"post\">");
        formSecurityToken();
        $ips = @file(DOKU_CONF.'iptrust.conf', FILE_SKIP_EMPTY_LINES);
        if ($ips && (sizeof($ips) > 0)) {
            usort($ips, array($this, 'sort_ip'));
            ptln("<table class=\"inline\">");
            ptln("<colgroup width=\"250\"></colgroup>");
            ptln("<thead>");
            ptln("<tr>");
            ptln("<th>".$this->getLang('ip_addr')."</th>");
            ptln("<th>".$this->getLang('delete')."</th>");
            ptln("</tr>");
            ptln("</thead>");
            ptln("<tbody>");
            foreach ($ips as $ip) {
                $ip = rtrim($ip);
                ptln("<tr>");
                ptln("<td>".rtrim($ip)."</td>");
                ptln("<td>");
                ptln("<input type=\"submit\" name=\"delete[".$ip."]\" value=\"".$this->getLang('delete')."\" class=\"button\">");
                ptln("</td>");
                ptln("</tr>");
            }
            ptln("</tbody>");
            ptln("</table>");
        } else {
            ptln("<div class=\"fn\">".$this->getLang('noips')."</div>");
        }
        ptln("</form>");
        ptln("</div>");

        print $this->locale_xhtml('add');
        ptln("<div class=\"level2\">");
        ptln("<form action=\"\" method=\"post\">");
        formSecurityToken();
        ptln("<label for=\"ip__add\">".$this->getLang('ip_addr').":</label>");
        ptln("<input id=\"ip__add\" name=\"ip\" type=\"text\" maxlength=\"32\" class=\"edit\">");
        ptln("<input type=\"submit\" value=\"".$this->getLang('add')."\" class=\"button\">");
        ptln("</form>");
        ptln("</div>");

        if ($this->getConf('log_networks')) {
            print $this->locale_xhtml('access');
            ptln("<div class=\"level2\">");
            ptln("<form action=\"\" method=\"post\">");
            formSecurityToken();
            $logins = @file($conf['cachedir'].'/iptrust', FILE_SKIP_EMPTY_LINES);
            if ($logins && (sizeof($logins) > 0)) {
                usort($logins, array($this, 'sort_login'));
                $count = sizeof($logins);
                ptln("<table class=\"inline\">");
                ptln("<thead>");
                ptln("<tr>");
                ptln("<th>".$this->getLang('ip_addr')."</th>");
                ptln("<th>".$this->getLang('user')."</th>");
                ptln("<th>".$this->getLang('date')."</th>");
                ptln("<th>".$this->getLang('add')."</th>");
                ptln("</tr>");
                ptln("</thead>");
                ptln("<tbody>");
                for ($i = 0; $i < sizeof($logins);) {
                    list($user, $ip, $date) = explode("\t", $logins[$i]);
                    if ($ips && in_array($ip."\n", $ips)) {
                        array_splice($logins, $i, 1);
                    } else {
                        ptln("<tr>");
                        ptln("<td>".$ip."</td>");
                        ptln("<td>".$user."</td>");
                        ptln("<td>".strftime($conf['dformat'], $date)."</td>");
                        ptln("<td>");
                        ptln("<input type=\"submit\" name=\"add[".$ip."]\" value=\"".$this->getLang('add')."\" class=\"button\">");
                        ptln("</td>");
                        ptln("</tr>");
                        $i++;
                    }
                }
                ptln("</tbody>");
                ptln("</table>");
                ptln("<input type=\"submit\" name=\"clear\" value=\"".$this->getLang('clear')."\" class=\"button\">");
                if (sizeof($logins) < $count) {
                    io_saveFile($conf['cachedir'].'/iptrust', join('', $logins));
                }
            }
            ptln("</form>");
            ptln("</div>");
        } else {
            if (file_exists($conf['cachedir'].'/iptrust')) {
                @unlink($conf['cachedir'].'/iptrust');
            }
        }
    }

    /**
     * Sorts IP addresses array
     */
    function sort_ip($a, $b) {
        return (ip2long($a) - ip2long($b));
    }

    /**
     * Sorts logins array
     */
    function sort_login($a, $b) {
        list($auser, $aip, $adate) = explode("\t", $a);
        list($buser, $bip, $bdate) = explode("\t", $b);
        return ($bdate - $adate);
    }

}
