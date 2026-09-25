// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	awsconf "github.com/aws/aws-sdk-go-v2/config"
	"github.com/cockroachdb/errors"
	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	rawsftp "github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/awsinstanceconnect"
	"go.mondoo.com/mql/providers/os/connection/ssh/awsssmsession"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"go.mondoo.com/mql/providers/os/connection/ssh/scp"
	"go.mondoo.com/mql/providers/os/connection/ssh/sftp"
	"go.mondoo.com/mql/providers/os/connection/ssh/signers"
	"go.mondoo.com/mql/utils/multierr"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	_ shared.Connection = (*Connection)(nil)
	_ plugin.Closer     = (*Connection)(nil)
)

type Connection struct {
	plugin.Connection
	conf  *inventory.Config
	asset *inventory.Asset

	fs   afero.Fs
	Sudo *inventory.Sudo

	serverVersion    string
	UseScpFilesystem bool
	HostKey          ssh.PublicKey
	SSHClient        *ssh.Client
}

func NewConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*Connection, error) {
	res := Connection{
		Connection: plugin.NewConnection(id, asset),
		conf:       conf,
		asset:      asset,
	}

	host := conf.GetHost()

	// ipv6 addresses w/o the surrounding [] will eventually error
	// so check whether we have an ipv6 address by parsing it (the
	// parsing will fail if the string DOES have the []s) and adding
	// the []s
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		conf.Host = "[" + host + "]"
	}

	conf = readSSHConfig(conf)
	if err := verifyConfig(conf); err != nil {
		return nil, err
	}

	if os.Getenv("MONDOO_SSH_SCP") == "on" || conf.Options["ssh_scp"] == "on" {
		log.Debug().Msg("use scp file transfer")
		res.UseScpFilesystem = true
	}

	if conf.Insecure {
		log.Debug().Msg("user allowed insecure ssh connection")
	}

	if err := res.Connect(); err != nil {
		return nil, err
	}

	// check uid of user and disable sudo if uid is 0
	if conf.Sudo != nil && conf.Sudo.Active {
		// the id command may not be available, eg. if ssh is used with windows
		out, _ := res.RunCommand("id -u")
		stdout, _ := io.ReadAll(out.Stdout)
		// just check for the explicit positive case, otherwise just activate sudo
		// we check sudo in VerifyConnection
		if string(stdout) != "0" {
			// configure sudo
			log.Debug().Msg("activated sudo for ssh connection")
			res.Sudo = conf.Sudo
		} else {
			log.Debug().Msg("deactivated sudo for ssh connection since user is root")
		}
	}

	// verify connection
	vErr := res.verify()
	// NOTE: for now we do not enforce connection verification to ensure we cover edge-cases
	// TODO: in following minor version bumps, we want to enforce this behavior to ensure proper scans
	if vErr != nil {
		log.Warn().Err(vErr).Send()
	}

	return &res, nil
}

func (c *Connection) Name() string {
	return "ssh"
}

func (c *Connection) Type() shared.ConnectionType {
	return shared.Type_SSH
}

func (p *Connection) Asset() *inventory.Asset {
	return p.asset
}

func (p *Connection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (p *Connection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

func (c *Connection) RunCommand(command string) (*shared.Command, error) {
	if c.Sudo != nil && c.Sudo.Active {
		command = shared.BuildSudoCommand(c.Sudo, command)
	}
	return c.runRawCommand(command)
}

func (c *Connection) runRawCommand(command string) (*shared.Command, error) {
	log.Debug().Str("command", command).Str("provider", "ssh").Msg("run command")

	if c.SSHClient == nil {
		return nil, errors.New("SSH session not established")
	}

	res := shared.Command{
		Command: command,
		Stats: shared.PerfStats{
			Start: time.Now(),
		},
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	}
	defer func() {
		res.Stats.Duration = time.Since(res.Stats.Start)
	}()

	session, err := c.SSHClient.NewSession()
	if err != nil {
		log.Debug().Msg("could not open new session, try to re-establish connection")

		c.Close()
		if err = c.Connect(); err != nil {
			return nil, multierr.Wrap(err, "failed to open SSH session (reconnect failed)")
		}

		session, err = c.SSHClient.NewSession()
		if err != nil {
			return nil, err
		}
	}
	defer session.Close()

	// start ssh call
	session.Stdout = res.Stdout
	session.Stderr = res.Stderr
	err = session.Run(res.Command)
	if err == nil {
		return &res, nil
	}

	// if the program failed, we do not return err but its exit code
	var e *ssh.ExitError
	match := errors.As(err, &e)
	if match {
		res.ExitStatus = e.ExitStatus()
		return &res, nil
	}

	// all other errors are real errors and not expected
	return &res, err
}

func (c *Connection) FileSystem() afero.Fs {
	if c.fs != nil {
		return c.fs
	}

	// log the used ssh filesystem backend
	defer func() {
		log.Debug().Str("file-transfer", c.fs.Name()).Msg("initialized ssh filesystem")
	}()

	//// detect cisco network gear, they returns something like SSH-2.0-Cisco-1.25
	//// NOTE: we need to understand why this happens
	//if strings.Contains(strings.ToLower(t.serverVersion), "cisco") {
	//	log.Debug().Msg("detected cisco device, deactivate file system support")
	//	t.fs = &fsutil.NoFs{}
	//	return t.fs
	//}

	if c.Sudo != nil && c.Sudo.Active {
		c.fs = cat.New(c)
		return c.fs
	}

	// we always try to use sftp first (if scp is not user-enforced)
	// and we also fallback to scp if sftp does not work
	if !c.UseScpFilesystem {
		fs, err := sftp.New(c, c.SSHClient)
		if err != nil {
			log.Info().Msg("use scp instead of sftp")
			// enable fallback
			c.UseScpFilesystem = true
		} else {
			c.fs = fs
			return c.fs
		}
	}

	if c.UseScpFilesystem {
		c.fs = scp.NewFs(c, c.SSHClient)
		return c.fs
	}

	// always fallback to catfs, slow but it works
	c.fs = cat.New(c)
	return c.fs
}

func (c *Connection) FileInfo(path string) (shared.FileInfoDetails, error) {
	fs := c.FileSystem()
	afs := &afero.Afero{Fs: fs}

	// Use Lstat as the primary call when available (SFTP has it). For
	// non-symlinks the result is identical to Stat with no extra cost.
	// For symlinks we call Stat once more to get the target's metadata.
	type lstater interface {
		Lstat(string) (os.FileInfo, error)
	}
	if ls, ok := fs.(lstater); ok {
		linfo, err := ls.Lstat(path)
		if err != nil {
			return shared.FileInfoDetails{}, err
		}

		if linfo.Mode()&os.ModeSymlink != 0 {
			stat, err := afs.Stat(path)
			if err != nil {
				if !os.IsNotExist(err) {
					return shared.FileInfoDetails{}, err
				}
				// Dangling symlink: target doesn't exist.
				return shared.FileInfoDetails{
					Mode: shared.FileModeDetails{FileMode: linfo.Mode()},
					Size: linfo.Size(),
					Uid:  -1,
					Gid:  -1,
				}, nil
			}
			uid, gid := c.extractOwnership(stat)
			return shared.FileInfoDetails{
				Mode: shared.FileModeDetails{FileMode: stat.Mode() | os.ModeSymlink},
				Size: stat.Size(),
				Uid:  uid,
				Gid:  gid,
			}, nil
		}

		// Not a symlink — lstat result is the final answer.
		uid, gid := c.extractOwnership(linfo)
		return shared.FileInfoDetails{
			Mode: shared.FileModeDetails{FileMode: linfo.Mode()},
			Size: linfo.Size(),
			Uid:  uid,
			Gid:  gid,
		}, nil
	}

	// Fallback for filesystems without Lstat (cat, SCP).
	// Symlink detection handled by statutil's compound command.
	stat, err := afs.Stat(path)
	if err != nil {
		return shared.FileInfoDetails{}, err
	}
	uid, gid := c.extractOwnership(stat)
	return shared.FileInfoDetails{
		Mode: shared.FileModeDetails{FileMode: stat.Mode()},
		Size: stat.Size(),
		Uid:  uid,
		Gid:  gid,
	}, nil
}

func (c *Connection) extractOwnership(stat os.FileInfo) (uid, gid int64) {
	uid, gid = -1, -1
	if c.Sudo != nil || c.UseScpFilesystem {
		if si, ok := stat.Sys().(*shared.FileInfo); ok {
			uid = si.Uid
			gid = si.Gid
		}
	} else {
		if si, ok := stat.Sys().(*rawsftp.FileStat); ok {
			uid = int64(si.UID)
			gid = int64(si.GID)
		}
	}
	return
}

func (c *Connection) Close() {
	if c.SSHClient != nil {
		c.SSHClient.Close()
	}
}

// checks the connection config and set default values if not provided by the user
func (c *Connection) setDefaultSettings() {
	// we always want to ensure we use the default port if nothing was specified
	if c.conf.Port == 0 {
		c.conf.Port = 22
	}

	// we need to check if an executable was provided, otherwise fallback to use sudo
	if c.conf.Sudo != nil && c.conf.Sudo.Active && c.conf.Sudo.Executable == "" {
		c.conf.Sudo.Executable = "sudo"
	}
}

func (c *Connection) Connect() error {
	cc := c.conf

	c.setDefaultSettings()

	// load known hosts and track the fingerprint of the ssh server for later identification
	knownHostsCallback, err := knownHostsCallback()
	if err != nil {
		return multierr.Wrap(err, "could not read hostkey file")
	}

	var hostkey ssh.PublicKey
	hostkeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// store the hostkey for later identification
		hostkey = key

		// ignore hostkey check if the user provided an insecure flag
		if cc.Insecure {
			return nil
		}

		// knownhost.New returns a ssh.CertChecker which does not work with all ssh.HostKey types
		// especially the newer edcsa keys (ssh.curve25519sha256) are not well supported.
		// https://github.com/golang/crypto/blob/master/ssh/knownhosts/knownhosts.go#L417-L436
		// creates the CertChecker which requires an instance of Certificate
		// https://github.com/golang/crypto/blob/master/ssh/certs.go#L326-L348
		// https://github.com/golang/crypto/blob/master/ssh/keys.go#L271-L283
		// therefore it is best to skip the checking for now since it forces users to set the insecure flag otherwise
		// TODO: implement custom host-key checking for normal public keys as well
		_, ok := key.(*ssh.Certificate)
		if !ok {
			log.Debug().Msg("skip hostkey check the hostkey since the algo is not supported yet")
			return nil
		}

		err := knownHostsCallback(hostname, remote, key)
		if err != nil {
			log.Debug().Err(err).Str("hostname", hostname).Str("ip", remote.String()).Msg("check known host")
		}
		return err
	}

	// establish connection
	conn, _, err := establishClientConnection(cc, hostkeyCallback)
	if err != nil {
		log.Debug().Err(err).Str("provider", "ssh").Str("host", cc.Host).Int32("port", cc.Port).Bool("insecure", cc.Insecure).Msg("could not establish ssh session")
		if strings.ContainsAny(cc.Host, "[]") {
			log.Info().Str("host", cc.Host).Int32("port", cc.Port).Msg("ensure proper []s when combining IPv6 with port numbers")
		}
		return err
	}
	c.SSHClient = conn
	c.HostKey = hostkey
	c.serverVersion = string(conn.ServerVersion())
	log.Debug().Str("provider", "ssh").Str("host", cc.Host).Int32("port", cc.Port).Str("server", c.serverVersion).Msg("ssh session established")
	return nil
}

func (c *Connection) PlatformID() (string, error) {
	return PlatformIdentifier(c.HostKey), nil
}

func PlatformIdentifier(publicKey ssh.PublicKey) string {
	fingerprint := ssh.FingerprintSHA256(publicKey)
	fingerprint = strings.Replace(fingerprint, ":", "-", 1)
	identifier := "//platformid.api.mondoo.app/runtime/ssh/hostkey/" + fingerprint
	return identifier
}

func readSSHConfig(cc *inventory.Config) *inventory.Config {
	host := cc.Host

	home, err := homedir.Dir()
	if err != nil {
		log.Debug().Err(err).Msg("ssh> failed to determine user home directory")
		return cc
	}

	sshUserConfigPath := filepath.Join(home, ".ssh", "config")
	f, err := os.Open(sshUserConfigPath)
	if err != nil {
		log.Debug().Err(err).Str("file", sshUserConfigPath).Msg("ssh> could not read ssh config")
		return cc
	}

	cfg, err := ssh_config.Decode(f)
	if err != nil {
		log.Debug().Err(err).Str("file", sshUserConfigPath).Msg("could not parse ssh config")
		return cc
	}

	// optional step, tries to parse the ssh config to see if additional information
	// is already available
	hostname, err := cfg.Get(host, "HostName")
	if err == nil && len(hostname) > 0 {
		cc.Host = hostname
	}

	if len(cc.Credentials) == 0 || (len(cc.Credentials) == 1 && cc.Credentials[0].Type == vault.CredentialType_password && len(cc.Credentials[0].Secret) == 0) {
		user, _ := cfg.Get(host, "User")
		port, err := cfg.Get(host, "Port")
		if err == nil {
			portNum, err := strconv.Atoi(port)
			if err != nil {
				log.Debug().Err(err).Str("file", sshUserConfigPath).Str("port", port).Msg("could not parse ssh port")
			} else {
				cc.Port = int32(portNum)
			}
		}

		entry, err := cfg.Get(host, "IdentityFile")

		// TODO: the ssh_config uses os/home but instead should be use go-homedir, could become a compile issue
		// TODO: the problem is that the lib returns defaults and we cannot properly distinguish
		if err == nil && ssh_config.Default("IdentityFile") != entry {
			// commonly ssh config included paths like ~
			expandedPath, err := homedir.Expand(entry)
			if err == nil {
				log.Debug().Str("key", expandedPath).Str("host", host).Msg("ssh> read ssh identity key from ssh config")
				// NOTE: we ignore the error here for now but this should probably been caught earlier anyway
				credential, _ := vault.NewPrivateKeyCredentialFromPath(user, expandedPath, "")
				// apply the option manually
				if credential != nil {
					cc.Credentials = append(cc.Credentials, credential)
				}
			}
		}
	}

	// handle disable of strict hostkey checking:
	// Host *
	// StrictHostKeyChecking no
	entry, err := cfg.Get(host, "StrictHostKeyChecking")
	if err == nil && strings.ToLower(entry) == "no" {
		cc.Insecure = true
	}
	return cc
}

func verifyConfig(conf *inventory.Config) error {
	if conf.Type != "ssh" {
		return inventory.ErrProviderTypeDoesNotMatch
	}

	return nil
}

func knownHostsCallback() (ssh.HostKeyCallback, error) {
	home, err := homedir.Dir()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to determine user home directory")
		return nil, err
	}

	// load default host keys
	files := []string{
		filepath.Join(home, ".ssh", "known_hosts"),
		// see https://cloud.google.com/compute/docs/instances/connecting-to-instance
		// NOTE: content in that file is structured by compute.instanceid key
		// TODO: we need to keep the instance information during the resolve step
		filepath.Join(home, ".ssh", "google_compute_known_hosts"),
	}

	// filter all files that do not exits
	existentKnownHosts := []string{}
	for i := range files {
		_, err := os.Stat(files[i])
		if err == nil {
			log.Debug().Str("file", files[i]).Msg("load ssh known_hosts file")
			existentKnownHosts = append(existentKnownHosts, files[i])
		}
	}

	return knownhosts.New(existentKnownHosts...)
}

func establishClientConnection(pCfg *inventory.Config, hostKeyCallback ssh.HostKeyCallback) (*ssh.Client, []io.Closer, error) {
	authMethods, closer, err := prepareConnection(pCfg)
	if err != nil {
		return nil, nil, err
	}

	if len(authMethods) == 0 {
		return nil, nil, errors.New("no authentication method defined")
	}

	// TODO: hack: we want to establish a proper connection per configured connection so that we could use multiple users
	user := ""
	for i := range pCfg.Credentials {
		if pCfg.Credentials[i].User != "" {
			user = pCfg.Credentials[i].User
		}
	}

	addr := pCfg.Host + ":" + strconv.Itoa(int(pCfg.Port))
	sshClientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
	}

	supportsHybrid, err := serverSupportsHybridKEX(addr)
	if err == nil && supportsHybrid {
		// force the Key Exchange Algorithm to a compatible one
		sshClientConfig.Config = ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"diffie-hellman-group14-sha1",
			},
		}
	}

	log.Debug().
		Int("methods", len(authMethods)).
		Str("user", user).
		Bool("hybrid_key_exchange", supportsHybrid).
		Msg("connect to remote ssh")
	conn, err := ssh.Dial("tcp", addr, sshClientConfig)
	return conn, closer, err
}

// Detects if the remote server offers hybrid PQ KEX algorithms
func serverSupportsHybridKEX(addr string) (bool, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Debug().Err(err).Msg("fail to verify KEX algorithms")
		return false, err
	}
	defer conn.Close()

	// Read the server's version string
	var buf [256]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		return false, errors.Wrap(err, "failed to read banner")
	}
	banner := string(buf[:n])

	// We'll stop here. Full KEXINIT parsing requires building a custom packet reader.
	// For now, assume OpenSSH 9.9+ includes PQ KEX unless we detect otherwise.
	if strings.Contains(banner, "OpenSSH_9.9") {
		// Naively assume 9.9+ offers hybrid KEX
		return true, nil
	}

	return false, nil
}

// prepareConnection determines the auth methods required for a ssh connection and also prepares any other
// pre-conditions for the connection like tunnelling the connection via AWS SSM session
func prepareConnection(conf *inventory.Config) ([]ssh.AuthMethod, []io.Closer, error) {
	auths := []ssh.AuthMethod{}
	closer := []io.Closer{}

	// only one public auth method is allowed, therefore multiple keys need to be encapsulated into one auth method
	sshSigners := []ssh.Signer{}

	// if no credential was provided, fallback to ssh-agent and ssh-config
	if len(conf.Credentials) == 0 {
		sshSigners = append(sshSigners, signers.GetSignersFromSSHAgent()...)
	}

	// use key auth, only load if the key was not found in ssh agent
	for i := range conf.Credentials {
		credential := conf.Credentials[i]

		switch credential.Type {
		case vault.CredentialType_private_key:
			log.Debug().Msg("enabled ssh private key authentication")
			priv, err := signers.GetSignerFromPrivateKeyWithPassphrase(credential.Secret, []byte(credential.Password))
			if err != nil {
				log.Debug().Err(err).Msg("could not read private key")
			} else {
				sshSigners = append(sshSigners, priv)
			}
		case vault.CredentialType_password:
			// use password auth if the password was set, this is also used when only the username is set
			if len(credential.Secret) > 0 {
				log.Debug().Msg("enabled ssh password authentication")
				auths = append(auths, ssh.Password(string(credential.Secret)))

				// some systems like PAM do not use password but keyboard interactive
				auths = append(auths, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
					res := []string{}

					for _, q := range questions {
						if strings.Contains(strings.ToLower(q), "password") {
							res = append(res, string(credential.Secret))
						} else {
							res = append(res, "")
						}
					}

					return res, nil
				}))
			}
		case vault.CredentialType_ssh_agent:
			log.Debug().Msg("enabled ssh agent authentication")
			sshSigners = append(sshSigners, signers.GetSignersFromSSHAgent()...)
		case vault.CredentialType_aws_ec2_ssm_session:
			// when the user establishes the ssm session we do the following
			// 1. start websocket connection and start the session-manager-plugin to map the websocket to a local port
			// 2. create new ssh key via instance connect so that we do not rely on any pre-existing ssh key
			err := awsssmsession.CheckPlugin()
			if err != nil {
				return nil, nil, errors.New("Local AWS Session Manager plugin is missing. See https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html for information on the AWS Session Manager plugin and installation instructions")
			}

			loadOpts := []func(*awsconf.LoadOptions) error{}
			if conf.Options != nil && conf.Options["region"] != "" {
				loadOpts = append(loadOpts, awsconf.WithRegion(conf.Options["region"]))
			}
			profile := ""
			if conf.Options != nil && conf.Options["profile"] != "" {
				loadOpts = append(loadOpts, awsconf.WithSharedConfigProfile(conf.Options["profile"]))
				profile = conf.Options["profile"]
			}
			log.Debug().Str("profile", conf.Options["profile"]).Str("region", conf.Options["region"]).Msg("using aws creds")

			cfg, err := awsconf.LoadDefaultConfig(context.Background(), loadOpts...)
			if err != nil {
				return nil, nil, err
			}

			// we use ec2 instance connect api to create credentials for an aws instance
			eic := awsinstanceconnect.New(cfg)
			host := conf.Host
			if id, ok := conf.Options["instance"]; ok {
				host = id
			}
			creds, err := eic.GenerateCredentials(host, credential.User)
			if err != nil {
				return nil, nil, err
			}

			// we use ssm session manager to connect to instance via websockets
			sManager, err := awsssmsession.NewAwsSsmSessionManager(cfg, profile)
			if err != nil {
				return nil, nil, err
			}

			// prepare websocket connection and bind it to a free local port
			localIp := "localhost"
			remotePort := "22"
			// NOTE: for SSM we always target the instance id
			conf.Host = creds.InstanceId
			localPort, err := awsssmsession.GetAvailablePort()
			if err != nil {
				return nil, nil, errors.New("could not find an available port to start the ssm proxy")
			}
			ssmConn, err := sManager.Dial(conf, strconv.Itoa(localPort), remotePort)
			if err != nil {
				return nil, nil, err
			}

			// update endpoint information for ssh to connect via local ssm proxy
			// TODO: this has a side-effect, we may need extend the struct to include resolved connection data
			conf.Host = localIp
			conf.Port = int32(localPort)

			// NOTE: we need to set insecure so that ssh does not complain about the host key
			// It is okay do that since the connection is established via aws api itself and it ensures that
			// the instance id is okay
			conf.Insecure = true

			// use the generated ssh credentials for authentication
			priv, err := signers.GetSignerFromPrivateKeyWithPassphrase(creds.KeyPair.PrivateKey, creds.KeyPair.Passphrase)
			if err != nil {
				return nil, nil, multierr.Wrap(err, "could not read generated private key")
			}
			sshSigners = append(sshSigners, priv)
			closer = append(closer, ssmConn)
		case vault.CredentialType_aws_ec2_instance_connect:
			log.Debug().Str("profile", conf.Options["profile"]).Str("region", conf.Options["region"]).Msg("using aws creds")

			loadOpts := []func(*awsconf.LoadOptions) error{}
			if conf.Options != nil && conf.Options["region"] != "" {
				loadOpts = append(loadOpts, awsconf.WithRegion(conf.Options["region"]))
			}
			if conf.Options != nil && conf.Options["profile"] != "" {
				loadOpts = append(loadOpts, awsconf.WithSharedConfigProfile(conf.Options["profile"]))
			}
			cfg, err := awsconf.LoadDefaultConfig(context.Background(), loadOpts...)
			if err != nil {
				return nil, nil, err
			}
			log.Debug().Msg("generating instance connect credentials")
			eic := awsinstanceconnect.New(cfg)
			host := conf.Host
			if id, ok := conf.Options["instance"]; ok {
				host = id
			}
			creds, err := eic.GenerateCredentials(host, credential.User)
			if err != nil {
				return nil, nil, err
			}

			priv, err := signers.GetSignerFromPrivateKeyWithPassphrase(creds.KeyPair.PrivateKey, creds.KeyPair.Passphrase)
			if err != nil {
				return nil, nil, multierr.Wrap(err, "could not read generated private key")
			}
			sshSigners = append(sshSigners, priv)

			// NOTE: this creates a side-effect where the host is overwritten
			conf.Host = creds.PublicIpAddress
		default:
			return nil, nil, errors.New("unsupported authentication mechanism for ssh: " + credential.Type.String())
		}
	}

	if len(sshSigners) > 0 {
		auths = append(auths, ssh.PublicKeys(sshSigners...))
	}

	return auths, closer, nil
}

func (c *Connection) verify() error {
	var out *shared.Command
	var err error
	if c.Sudo != nil {
		// Check sudo works, with proper error messages. /dev/null disables
		// stdin so a sudo that wants a password fails instead of hanging; it
		// is appended outside the quoted command so the redirect is the outer
		// shell's, not something sudo is asked to run.
		command := shared.BuildSudoCommand(c.Sudo, "echo hi") + " < /dev/null"
		out, err = c.runRawCommand(command)
	} else {
		out, err = c.runRawCommand("echo 'hi'")
	}
	if err != nil {
		return err
	}

	if out.ExitStatus == 0 {
		return nil
	}

	stderr, _ := io.ReadAll(out.Stderr)
	errMsg := string(stderr)

	// sample messages are:
	// sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
	// sudo: a password is required
	switch {
	case strings.Contains(errMsg, "not found"):
		return errors.New("sudo command is missing on target")
	case strings.Contains(errMsg, "a password is required"):
		return errors.New("could not establish connection: sudo password is not supported yet, configure password-less sudo")
	default:
		return errors.New("could not establish connection: " + errMsg)
	}
}
