This is the synology-sso gateway project

This project is for setting your synology gateway to use SSO for authentication.

you can use docker to run this project.

run the command 
```shell
docker run -e APP_ID={your app id in SSO server } -e FORWARD_URL={your real application homepage } -e OPENID_CONFIG_URL={https://xxxxx/webman/sso/.well-known/openid-configuration, xxxx is your sso server url} -e REDIRECT_URL={it should be the url of your sso proxy agent, I mean the url of this app.} -p 10000:10000 samliu960522/synology-sso-proxy-agent:latest
```

for using synology sso server, dont' forget expose 5001 port and 443 port for your sso server. in home server, you can forward these two port to 443, and 5001 to your router.