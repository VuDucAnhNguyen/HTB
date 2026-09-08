import re

with open("Mysql.wp5", 'r') as f:
    lines = f.readlines()

env = {}
output_lines = []

set_pattern = re.compile(r"set\s+([^=\r\n]+)=(.*)$", re.IGNORECASE)

var_pattern = re.compile(r"%([^%]+)%")

def resolve_vars(text, current_env):

    def replacer(match):
        var_name = match.group(1)
        for k, v in current_env.items():
            if k.lower() == var_name.lower():
                return v
        return match.group(0)

    prev = ""
    while prev != text:
        prev = text
        text = var_pattern.sub(replacer, text)
    return text



for line in lines:
    resolved_line = resolve_vars(line, env)

    match = set_pattern.match(resolved_line)
    if match:
        var_name = match.group(1).strip()
        var_val = match.group(2)
        env[var_name] = var_val

        output_lines.append(resolved_line)
    else:
        output_lines.append(resolved_line)

with open("Mysql_deobfuscated.bat", "w") as f:
    f.write("\n".join(output_lines))