const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const fs = require('fs')
const morgan = require('morgan')
const axios = require('axios')
const { performance } = require('perf_hooks')
const { SocksProxyAgent } = require('socks-proxy-agent')
const ConfigParser = require('configparser')
const { exec } = require('child_process')

app.use(bodyParser.json())
app.use(morgan('combined'))

const config = new ConfigParser()
config.read('config.conf')

const prefix = config.get('api', 'prefix')
const appPort = config.get('api', 'port')
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

//clearup runningprocess.txt file
fs.writeFile('runningprocess.txt', '', function (err) {
  if (err) throw err
})

app.listen(appPort, '0.0.0.0', () => {
  console.log(`Listening on port ${appPort}`)
})

async function parseConfig() {
  config.read('config.conf')
  const confList = config.sections()
  let digitaloceanConfigList = []
  let cloudflareConfig = {}
  let apiConfig = {}

  for (let i = 0; i < confList.length; i++) {
    const configName = confList[i]
    const configType = config.get(confList[i], 'type')
    if (configType == 'cloudflare') {
      const email = config.get(confList[i], 'email')
      const token = config.get(confList[i], 'token')
      const domain = config.get(confList[i], 'domain')
      const zoneId = config.get(confList[i], 'zoneId') || ''
      const configName = confList[i]
      cloudflareConfig.email = email
      cloudflareConfig.token = token
      cloudflareConfig.domain = domain
      cloudflareConfig.configName = configName
      cloudflareConfig.zoneId = zoneId
    } else if (configType == 'api') {
      const prefix = config.get(confList[i], 'prefix')
      const port = config.get(confList[i], 'port')
      const hostLocalIp = config.get(confList[i], 'hostLocalIp')
      const hostPublicIp = config.get(confList[i], 'hostPublicIp')
      const key = config.get(confList[i], 'key')
      const apiHostName = config.get(confList[i], 'apiHostName')
      apiConfig.prefix = prefix
      apiConfig.port = port
      apiConfig.hostLocalIp = hostLocalIp
      apiConfig.hostPublicIp = hostPublicIp
      apiConfig.key = key
      apiConfig.apiHostName = apiHostName
    } else if (configType == 'digitalocean') {
      const accessToken = config.get(confList[i], 'accessToken')
      const dropletId = config.get(confList[i], 'dropletId')
      const region = config.get(confList[i], 'region')
      const socks5Port = config.get(confList[i], 'socks5Port')
      const httpPort = config.get(confList[i], 'httpPort')
      const imageName = config.get(confList[i], 'imageName')
      const sizeSlug = config.get(confList[i], 'sizeSlug')
      const dropletName = config.get(confList[i], 'dropletName')
      const rootPassword = config.get(confList[i], 'rootPassword') || ''
      const sshKeys = config.get(confList[i], 'sshKeys') || ''
      const privateKeyPath = config.get(confList[i], 'privateKeyPath') || ''

      digitaloceanConfigList.push({
        configName: configName,
        accessToken: accessToken,
        dropletId: dropletId,
        region: region,
        socks5Port: socks5Port,
        httpPort: httpPort,
        imageName: imageName,
        sizeSlug: sizeSlug,
        dropletName: dropletName,
        rootPassword: rootPassword,
        sshKeys: sshKeys,
        privateKeyPath: privateKeyPath,
      })
    }
  }
  return {
    configs: {
      api: apiConfig,
      cloudflare: cloudflareConfig,
      digitalocean: digitaloceanConfigList,
    },
  }
}

async function checkCloudflare(serverConfig) {
  const cloudflareEmail = serverConfig.email
  const cloudflareKey = serverConfig.token
  const cloudflareDomain = serverConfig.domain
  const configName = serverConfig.configName
  let result = {}
  result.configName = configName
  try {
    const cf = require('cloudflare')({
      email: cloudflareEmail,
      key: cloudflareKey,
    })
    let zoneId = serverConfig.zoneId
    if (!zoneId) {
      zoneId = await cf.zones.browse().then((data) => {
        const zone = data.result.find((zone) => zone.name == cloudflareDomain)
        return zone.id
      })
      if (!zoneId) {
        return false
      }
    }
    result.zoneId = zoneId
    result.success = true
  } catch (err) {
    result.success = false
  }
  return result
}

async function checkDigitalOcean(serverConfig) {
  const accessToken = serverConfig.accessToken
  const dropletId = serverConfig.dropletId
  const configName = serverConfig.configName
  const socks5Port = serverConfig.socks5Port
  const httpPort = serverConfig.httpPort

  const doApi = axios.create({
    baseURL: 'https://api.digitalocean.com/v2',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  })

  let result = {}
  result.configName = configName
  result.socks5Port = socks5Port
  result.httpPort = httpPort

  try {
    const dropletResponse = await doApi.get(`/droplets/${dropletId}`)
    const droplet = dropletResponse.data.droplet
    
    result.ip = droplet.networks.v4.find((net) => net.type === 'public')?.ip_address || null
    result.ipType = 'Public IP (Dynamic)'; 

    if (result.ip) {
      result.success = true
    } else {
      result.success = false
      result.error = "No public IP found for this Droplet."
    }
  } catch (error) {
    result.success = false
    result.error = error.response ? error.response.data.message : error.message
  }
  return result
}

async function newIpDigitalOcean(serverConfig) {
  const accessToken = serverConfig.accessToken
  let dropletId = serverConfig.dropletId
  const configName = serverConfig.configName
  const regionSlug = serverConfig.region
  const imageName = serverConfig.imageName
  const sizeSlug = serverConfig.sizeSlug
  const sshKeys = serverConfig.sshKeys ? serverConfig.sshKeys.split(',').map(s => parseInt(s.trim())) : []
  const dropletName = serverConfig.dropletName
  const rootPassword = serverConfig.rootPassword
  const privateKeyPath = serverConfig.privateKeyPath

  const doApi = axios.create({
    baseURL: 'https://api.digitalocean.com/v2',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  })

  let oldIp = null
  let newIp = null

  try {
    // 1. Ambil IP lama dari Droplet saat ini (sebelum dihapus)
    try {
        const existingDropletResponse = await doApi.get(`/droplets/${droletId}`);
        oldIp = existingDropletResponse.data.droplet.networks.v4.find((net) => net.type === 'public')?.ip_address || null;
        console.log(`[DO] Found existing Droplet IP: ${oldIp}`);
    } catch (err) {
        console.warn(`[DO] Droplet with ID ${dropletId} not found or inaccessible. Assuming it needs to be created.`);
        oldIp = null;
    }

    // 2. Destroy Droplet lama (jika ada)
    if (dropletId) {
        console.log(`[DO] Destroying Droplet with ID: ${dropletId}...`);
        await doApi.delete(`/droplets/${dropletId}`);
        console.log(`[DO] Droplet ${dropletId} destruction initiated.`);
        
        let retries = 0;
        const maxDeleteRetries = 60;
        while (retries < maxDeleteRetries) {
            await sleep(2000);
            try {
                await doApi.get(`/droplets/${dropletId}`);
                console.log(`[DO] Waiting for Droplet ${dropletId} to be fully destroyed...`);
                retries++;
            } catch (error) {
                if (error.response && error.response.status === 404) {
                    console.log(`[DO] Droplet ${dropletId} successfully destroyed.`);
                    break;
                }
                throw error;
            }
        }
        if (retries === maxDeleteRetries) {
            throw new Error(`[DO] Failed to verify Droplet ${dropletId} destruction after multiple retries.`);
        }
    } else {
        console.log(`[DO] No existing Droplet ID found in config, skipping destruction.`);
    }

    // 3. Buat Droplet baru dengan SSH Keys
    console.log(`[DO] Creating new Droplet with name "${dropletName}"...`);
    const createDropletPayload = {
      name: dropletName,
      region: regionSlug,
      size: sizeSlug,
      image: imageName,
      ssh_keys: sshKeys.length > 0 ? sshKeys : undefined,
    };

    if (!createDropletPayload.ssh_keys || createDropletPayload.ssh_keys.length === 0) {
        console.log(`[DO] No SSH keys provided, attempting password-based user_data for root.`);
        if (!rootPassword) {
            throw new Error(`[DO] rootPassword is required in config.conf if no sshKeys are provided.`);
        }
        createDropletPayload.user_data = `#cloud-config
users:
  - name: root
    passwd: ${rootPassword}
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
chpasswd: { expire: False }
runcmd:
  - apt update && apt install -y openssh-server
  - sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  - sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  - sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
  - systemctl restart sshd
`;
    } else {
        console.log(`[DO] SSH keys provided, relying on DigitalOcean's SSH key injection.`);
        createDropletPayload.user_data = `#cloud-config\n# SSH keys will be injected automatically by DigitalOcean.`;
    }

    const createDropletResponse = await doApi.post('/droplets', createDropletPayload);

    const newDropletId = createDropletResponse.data.droplet.id;
    newIp = createDropletResponse.data.droplet.networks.v4.find((net) => net.type === 'public')?.ip_address;
    console.log(`[DO] New Droplet ${dropletName} created with ID: ${newDropletId} and IP: ${newIp}`);

    config.set(configName, 'dropletId', newDropletId.toString());
    config.write('config.conf');
    console.log(`[DO] config.conf updated with new Droplet ID: ${newDropletId}`);
    
    let activeRetries = 0;
    const maxActiveRetries = 90;
    while (activeRetries < maxActiveRetries) {
        await sleep(2000);
        const statusResponse = await doApi.get(`/droplets/${newDropletId}`);
        const currentDropletStatus = statusResponse.data.droplet.status;
        const currentPublicIp = statusResponse.data.droplet.networks.v4.find((net) => net.type === 'public')?.ip_address;

        if (currentDropletStatus === 'active' && currentPublicIp) {
            console.log(`[DO] New Droplet ${newDropletId} is active with IP: ${currentPublicIp}.`);
            newIp = currentPublicIp;
            break;
        }
        console.log(`[DO] Waiting for new Droplet to become active and get IP... (Status: ${currentDropletStatus}) (Attempt ${activeRetries + 1}/${maxActiveRetries})`);
        activeRetries++;
    }
    if (activeRetries === maxActiveRetries) {
        throw new Error(`[DO] Failed to verify new Droplet ${newDropletId} activation and IP after multiple retries.`);
    }

    console.log(`[DO] Droplet is active. Waiting an additional 60 seconds for SSH service to start and cloud-init to finish...`);
    await sleep(60000);
    console.log(`[DO] Additional wait finished. Attempting SSH.`);

    // 4. Buka SSH ke Droplet baru dan jalankan script setup
    console.log(`[DO] Running setup script on new Droplet via SSH...`);
    
    let sshCommand;
    if (sshKeys.length > 0 && privateKeyPath) {
        sshCommand = `ssh -i "${privateKeyPath}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${newIp} "sudo -i curl https://raw.githubusercontent.com/WASYHU/iptables/refs/heads/main/one.sh | sudo bash -s"`;
        console.log(`[DO] Executing SSH command with Private Key: ${privateKeyPath}`);
    } else if (rootPassword) {
        console.warn(`[DO] No SSH keys path provided, falling back to password-based SSH (requires sshpass).`);
        sshCommand = `sshpass -p '${rootPassword}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${newIp} "sudo -i curl https://raw.githubusercontent.com/WASYHU/iptables/refs/heads/main/one.sh | sudo bash -s"`;
    } else {
        throw new Error(`[DO] Neither SSH Keys nor rootPassword provided for SSH authentication.`);
    }

    const sshExecPromise = new Promise((resolve, reject) => {
        let sshStdoutBuffer = '';
        let sshStderrBuffer = '';
        const child = exec(sshCommand, { timeout: 180000 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`[DO] SSH command failed: ${error}`);
                console.error(`[DO] SSH stderr: ${stderr}`);
                fs.appendFileSync('ssh_debug.log', `[${new Date().toISOString()}] SSH Command Failed for ${newIp}:\n`);
                fs.appendFileSync('ssh_debug.log', `STDOUT:\n${sshStdoutBuffer}\n`);
                fs.appendFileSync('ssh_debug.log', `STDERR:\n${sshStderrBuffer}\n`);
                fs.appendFileSync('ssh_debug.log', `Error: ${error.message}\n\n`);
                resolve({ success: false, error: error.message, stdout: sshStdoutBuffer, stderr: sshStderrBuffer });
            } else {
                console.log(`[DO] SSH setup script execution completed.`);
                resolve({ success: true, stdout: sshStdoutBuffer, stderr: sshStderrBuffer });
            }
        });

        child.stdout.on('data', (data) => {
            sshStdoutBuffer += data.toString();
        });
        child.stderr.on('data', (data) => {
            sshStderrBuffer += data.toString();
        });
    });
    await sshExecPromise;

    console.log(`[DO] Final wait finished.`);


    return { oldIp: oldIp, newIp: newIp }

  } catch (error) {
    console.error(`[DO] Error in newIpDigitalOcean for ${configName}:`, error.response ? error.response.data : error.message)
    throw error
  }
}

app.get(`/${prefix}/newip/`, async (req, res) => {
  const startTime = performance.now()
  let configName = req.query.configName
  let port = req.query.port
  const { configs } = await parseConfig()

  if (!configName && !port) {
    return res
      .status(400)
      .json({ success: false, error: 'bad request, no query found' })
  }
  if (configName && port) {
    return res.status(400).json({
      success: false,
      error: 'bad request, only accept one query (configName/port)',
    })
  }

  if (!configName) {
    try {
      const digitaloceanConfig = configs.digitalocean.find(
        (config) => config.socks5Port == port || config.httpPort == port
      )

      const foundConfig = digitaloceanConfig

      if (!foundConfig) {
        return res.status(400).json({
          success: false,
          error: `bad request, no config found with port ${port}`,
        })
      }

      configName = foundConfig.configName
    } catch (err) {
      console.error(err)
      return res.status(500).json({ success: false, error: err.message })
    }
  }
  console.log(`hit newip ${configName}`)
  let result = {}
  try {
    const apiConfig = configs.api
    const appPort = apiConfig.port
    const apiHostName = apiConfig.apiHostName
    const cloudflareConfig = configs.cloudflare
    const domain = cloudflareConfig.domain
    const email = cloudflareConfig.email
    const token = cloudflareConfig.token
    const hostLocalIp = apiConfig.hostLocalIp
    const hostPublicIp = apiConfig.hostPublicIp
    const host = `${configName}.${domain}`
    const configType = config.get(configName, 'type')
    if (!configType || configType !== 'digitalocean') {
      return res.status(400).json({ success: false, error: 'config not found or not a DigitalOcean config' })
    }
    
    let runningProcess = fs.readFileSync('runningprocess.txt', 'utf8')
    let runningProcessArray = runningProcess.split('\n')
    let runningProcessIndex = runningProcessArray.findIndex((line) =>
      line.includes(`${configName}|`)
    )
    
    if (runningProcessIndex != -1) {
      let runningTime = runningProcessArray[runningProcessIndex].split('|')[1]
      if (Date.now() - runningTime > 60000) {
        runningProcessArray.splice(runningProcessIndex, 1)
        fs.writeFileSync('runningprocess.txt', runningProcessArray.join('\n'))
      } else {
        return res
          .status(200)
          .json({ success: false, message: 'already running' })
      }
    }
    
    runningProcessArray.push(`${configName}|${Date.now()}`)
    fs.writeFileSync('runningprocess.txt', runningProcessArray.join('\n'))

    exec(`systemctl stop sslocal_${configName}`, (err, stdout, stderr) => {
      if (err) {
        console.error(`Error stopping service: ${err}`)
        // Do not return here, continue with IP rotation
      }
    })
    let serverConfig
    if (configType == 'digitalocean') {
      serverConfig = configs.digitalocean.find(
        (config) => config.configName == configName
      )
      result = await newIpDigitalOcean(serverConfig)
    }
    const socks5Port = serverConfig.socks5Port
    const httpPort = serverConfig.httpPort
    const publicIp = result.newIp
    
    console.log(
      `profile: ${configName}, old ip: ${result.oldIp}, new ip: ${result.newIp}`
    )
    const cf = require('cloudflare')({
      email: email,
      key: token,
    })
    let zoneId = cloudflareConfig.zoneId
    if (!zoneId) {
      zoneId = await cf.zones.browse().then((data) => {
        const zone = data.result.find((zone) => zone.name == domain)
        return zone.id || cloudflareConfig.zoneId
      })
    }
      const apiHostNameRecord = await cf.dnsRecords
        .browse(zoneId)
        .then((data) => {
          const record = data.result.find((record) => record.name == apiHostName)
          return record
        })
      if (apiHostNameRecord == undefined) {
        await cf.dnsRecords.add(zoneId, {
          type: 'A',
          name: apiHostName,
          content: hostPublicIp,
          ttl: 1,
          proxied: false,
        })
      } else if (apiHostNameRecord.content != hostPublicIp) {
        await cf.dnsRecords.edit(zoneId, apiHostNameRecord.id, {
          type: 'A',
          name: apiHostName,
          content: hostPublicIp,
          ttl: 1,
          proxied: false,
        })
      }

    const configPath = `/etc/shadowsocks/config_${configName}.json`
    const configTemplate = fs.readFileSync('configtemplate.json', 'utf8')
    const configTemplateJson = JSON.parse(configTemplate)
    configTemplateJson.server = publicIp
    configTemplateJson.server_port = 8388
    configTemplateJson.password = 'Pass'
    configTemplateJson.method = 'aes-128-gcm'
    configTemplateJson.mode = 'tcp_and_udp'
    configTemplateJson.local_address = hostLocalIp
    configTemplateJson.locals[0].local_address = hostLocalIp
    configTemplateJson.local_port = parseInt(socks5Port)
    configTemplateJson.locals[0].local_port = parseInt(httpPort)
    if (!fs.existsSync('/etc/shadowsocks')) {
      fs.mkdirSync('/etc/shadowsocks')
    }
    if (!fs.existsSync(configPath)) {
      try {
        fs.writeFileSync(configPath, '')
        console.log(`Config file ${configPath} created successfully.`)
      } catch (err) {
        console.error(`Error creating config file: ${err}`)
      }
    } else {
      fs.writeFileSync(configPath, JSON.stringify(configTemplateJson))
      console.log(`Config file ${configPath} updated successfully.`)
    }

    const servicePath = `/etc/systemd/system/sslocal_${configName}.service`
    const serviceTemplate = fs.readFileSync('service_template.service', 'utf8')

    const serviceTemplateArray = serviceTemplate.split('\n')
    const serviceTemplateIndex = serviceTemplateArray.findIndex((line) =>
      line.includes('ExecStart')
    )
    serviceTemplateArray[
      serviceTemplateIndex
    ] = `ExecStart=/usr/local/bin/sslocal -c /etc/shadowsocks/config_${configName}.json`
    const newServiceTemplate = serviceTemplateArray.join('\n')
    fs.writeFileSync(servicePath, newServiceTemplate)
    
    await exec(`systemctl daemon-reload`)
    await exec(`systemctl start sslocal_${configName}.service`)
    let retry = 0
    let maxRetry = 10
    for (retry = 0; retry < maxRetry; retry++) {
      try {
        const socks5Url = `socks5://${hostPublicIp}:${socks5Port}`
        const agent = new SocksProxyAgent(socks5Url)
        console.log(`try to connect using ${socks5Url}`)
    
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 1000)
    
        const response = await axios.request({
          url: `http://${hostPublicIp}:${appPort}/${prefix}/ip`,
          method: 'GET',
          httpAgent: agent,
          httpsAgent: agent,
          signal: controller.signal,
        })
    
        clearTimeout(timeout)
    
        if (response.data === publicIp) {
          console.log(`Proxy matched public IP after ${retry + 1} try.`)
          break
        } else {
          console.warn(`Mismatch IP: got ${response.data}, expected ${publicIp}`)
        }
      } catch (err) {
        console.warn(`Attempt ${retry + 1} failed: ${err.message}`)
        await sleep(1000)
      }
    }    
    if (retry >= maxRetry) {
      throw new Error('retry proxy connection exceed maxRetry')
    }
    
    runningProcess = fs.readFileSync('runningprocess.txt', 'utf8')
    runningProcessArray = runningProcess.split('\n')
    runningProcessIndex = runningProcessArray.findIndex((line) =>
      line.includes(`${configName}|`)
    )
    runningProcessArray.splice(runningProcessIndex, 1)
    const newRunningProcess = runningProcessArray.join('\n')
    fs.writeFileSync('runningprocess.txt', newRunningProcess)
    result.proxy = {
      socks5: `${apiHostName}:${socks5Port}`,
      http: `${apiHostName}:${httpPort}`,
      shadowsocks: `${publicIp}:8388`,
    }
    result.configName = configName
    const endTime = performance.now()
    const executionTime = parseInt((endTime - startTime) / 1000)
    return res.status(200).json({
      success: true,
      result: {
        configName: configName,
        oldIp: result.oldIp,
        newIp: result.newIp,
        proxy: result.proxy,
      },
      executionTime: `${executionTime} seconds`,
    })
  } catch (err) {
    console.error(err)
    runningProcess = fs.readFileSync('runningprocess.txt', 'utf8')
    runningProcessArray = runningProcess.split('\n')
    runningProcessIndex = runningProcessArray.findIndex(
      (line) => line.includes(`${configName}|`) // Use includes to match
    )
    if (runningProcessIndex != -1) { // Only splice if found
        runningProcessArray.splice(runningProcessIndex, 1)
        const newRunningProcess = runningProcessArray.join('\n')
        fs.writeFileSync('runningprocess.txt', newRunningProcess)
    }
    const endTime = performance.now()
    const executionTime = parseInt((endTime - startTime) / 1000)
    return res.status(500).json({
      success: false,
      configName: configName,
      error: err.message,
      executionTime: `${executionTime} seconds`,
    })
  }
})

app.get(`/${prefix}/ip`, async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
    return res.status(200).send(ip)
  } catch (err) {
    return res.status(500).json({ message: err.message })
  }
})

app.get(`/${prefix}/checkConfig`, async (req, res) => {
  console.log('hit checkConfig')
  const { configs } = await parseConfig()
  const cloudflareConfig = configs.cloudflare
  const digitaloceanConfigList = configs.digitalocean
  let cloudflareCheckResult = {}
  let digitaloceanCheckResult = []

  try {
    cloudflareCheckResult = await checkCloudflare(cloudflareConfig)
    digitaloceanCheckResult = await Promise.all(
      digitaloceanConfigList.map((config) => checkDigitalOcean(config))
    )
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message })
  }
  return res.status(200).json({
    success: true,
    result: {
      cloudflare: cloudflareCheckResult,
      digitalocean: digitaloceanCheckResult,
    },
  })
})
