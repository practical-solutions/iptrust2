<?php
/**
 * Metadata for IPTrust Plugin
 *
 * @author    Andriy Lesyuk <andriy.lesyuk@softjourn.com>
 */

$meta['log_networks'] =
    array('string',
        '_pattern' => '!^[0-9]{1,3}\.(?:[0-9]{1,3}\.(?:[0-9]{1,3}\.(?:[0-9]{1,3})?)?)?'.
                      '(?:, *[0-9]{1,3}\.(?:[0-9]{1,3}\.(?:[0-9]{1,3}\.(?:[0-9]{1,3})?)?)?)*$!'
    );
