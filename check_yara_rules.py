import yara
import os
import socket
import git
import yara

def check_yara_rules(filename):
    try:
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        git.Git().clone("https://github.com/Yara-Rules/rules")
    except:
        pass

    total_rule = {}
    for yara_rule in os.listdir("rules/"):
        if os.path.isdir("rules/" + yara_rule):
            if not os.path.exists("rules_compiled"):
                os.mkdir("rules_compiled")
            if not os.path.exists("rules_compiled/" + yara_rule):
                os.mkdir("rules_compiled/" + yara_rule)

            for y_rule in os.listdir("rules/" + yara_rule):
                yara_rule_filepath = "rules/" + yara_rule + "/"
                yara_rule_compiled_filepath = "rules_compiled/" + yara_rule + "/"
                if not os.path.isdir("./" + y_rule):
                    try:
                        rule = yara.compile(yara_rule_filepath + y_rule)
                        rule.save(yara_rule_compiled_filepath + y_rule)
                        rule = yara.load(yara_rule_compiled_filepath + y_rule)
                        rule_match = rule.match(filename)
                        if rule_match:
                            name = y_rule.split(".")[0]
                            total_rule[name] = rule_match
                    except:
                        pass  # internal fatal error or warning
                else:
                    pass
    return total_rule


   