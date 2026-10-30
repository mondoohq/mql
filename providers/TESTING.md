# Arista Provider Testing

Need to test the Arista provider, but you don't have high end switches taking up space in your office? Don't worry, there are plenty of options for local or cloud testing so you can make sure this provider works as expected.

## AWS

### Launch the marketplace AMI

Launch an EC2 instance in the AWS Management Console. Search for the name `Arista CloudEOS Router (PAYG)`, which will show up in the Marketplace AMI tab.

**Note**: This subscription is $.45 an hour on top of a very large instance. Don't leave these running.

### Configure the security group

Mondoo scans the switch using the Arista API so you need to modify the security group to include **HTTPS** access. The easiest thing to do is just allow "All Traffic" from just your IP.

### SSH to the device

ssh ec2-user@DEVICE_PUBLIC_IP -i YOUR_KEY_PATH

**Note**: Arista will lock you out after multiple failed SSH attempts. If this happens just reboot the instance.

### Configure the host for scanning

```text
localhost> enable
localhost# config t
localhost(config)# username admin secret PICK_SOME_FANCY_PASSWORD
localhost(config)# management api http-commands
localhost(config-mgmt-api-http-cmds)# no shutdown
localhost(config-mgmt-api-http-cmds)# copy run start
Copy completed successfully.
```

### Enjoy your device

```text
mql shell arista DEVICE_PUBLIC_IP --ask-pass
Enter password:
→ loaded configuration from /Users/tsmith/.config/mondoo/mondoo.yml using source default
→ connected to Arista EOS
 _ __ ___   __ _| |
| '_ ` _ \ / _` | |
| | | | | | (_| | |
|_| |_| |_|\__, |_|
  mondoo™     |_|
 interactive shell

mql> arista.eos.hostname
arista.eos.hostname: "localhost"
```

## VirtualBox

Download the Arista VirtualBox image
https://arista.my.site.com/AristaCommunity/s/article/veos-and-virtualbox

Configure the VM:
https://www.youtube.com/watch?v=nbDF7hzBPM0

Configure SSH:
https://www.youtube.com/watch?v=QEmHqHpeoZM

SSH to the system:
```shell
ssh -p 2221 admin@localhost
```

Cancel zerotouch:
```text
localhost login:admin
localhost>zerotouch cancel
```

Configure IP for management:
```text
config
interface ma1
ip address dhcp
dhcp client accept default-route
end

show run int ma1
show int ma1
```

Configure user with password:
```text
en
config
username admin secret x245
```

Enable the eosAPI:
```text
login> admin
> en
Switch# configure terminal
  Switch(config)# management api http-commands
  Switch(config-mgmt-api-http-cmds)# no shutdown
  Switch(config-mgmt-api-http-cmds)# protocol ?
    http         Configure HTTP server options
    https        Configure HTTPS server options
    unix-socket  Configure Unix Domain Socket
  Switch(config-mgmt-api-http-cmds)# protocol http
  Switch(config-mgmt-api-http-cmds)# end

  Switch# show management api http-commands
  Enabled:            Yes
  HTTPS server:       running, set to use port 443
  HTTP server:        running, set to use port 80
  Local HTTP server:  shutdown, no authentication, set to use port 8080
  Unix Socket server: shutdown, no authentication
```

Enable password:
```text
en
config
enable password xyrt1
// deletes the enable password
no enable password
```

see https://www.arista.com/en/um-eos/eos-user-security

Enter bash mode

```text
switch#conf t
switch(config)#bash sudo su -
```

## Other useful information

Understanding eapi
https://arista.my.site.com/AristaCommunity/s/article/arista-eapi-101

expose api (requires port forwarding)
http://localhost:8080/explorer.html

arista user manual
https://www.arista.com/en/um-eos

vagrant setup (not tested)
https://github.com/jerearista/vagrant-veos
