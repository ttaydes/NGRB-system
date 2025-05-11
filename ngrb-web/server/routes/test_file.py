import yara

rules = yara.compile(filepath='../rules/backdoor_shamanic.yar')
matches = rules.match(filepath='shell.php')
