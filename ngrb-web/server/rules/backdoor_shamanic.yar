rule MAL_Generic_Backdoor_Template
{
    meta:
        description = "Generic backdoor or webshell detection"
        author = "aydes"
        date = "2025-05-08"
        malware_type = "backdoor"
        malware_family = "generic"
        threat_level = "suspicious"
        version = "1.0"

    strings:
        // 可选特征
        $input_stream = "php://input"
        $eval = /eval\s*\(.*\)/
        $base64 = "base64_decode"
        $xor_op = /[\$a-zA-Z0-9_]+\s*\^\s*[\$a-zA-Z0-9_]/
        $openssl = "openssl_decrypt"
        $call_func = "call_user_func"
        $cmd = /system\s*\(|exec\s*\(|shell_exec\s*\(/

    condition:
        2 of ($input_stream, $eval, $base64, $xor_op, $openssl, $call_func, $cmd)
}
