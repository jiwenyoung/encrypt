const { Command } = require('commander')
const chalk = require('chalk')
const fs = require('fs')
const util = require('util')
const crypto = require('crypto')
const scrypt = util.promisify(crypto.scrypt)
const randomFill = util.promisify(crypto.randomFill)
const path = require('path')
const prompt = require('prompt-sync')()

const main = async () => {
  try {
    const program = new Command();
    program.version('1.0.0');

    const algorithm = 'aes-192-cbc'
    const salt = 'gnsqyd4qxk'

    // DO
    const istextfile = (filepath, length) => {
      let char, buf;
      let fd = fs.openSync(filepath, 'r');
      length = length || 1000;
      for (let i = 0; i < length; i++) {
        buf = Buffer.alloc(1);
        let bytes = fs.readSync(fd, buf, 0, 1, i);
        char = buf.toString().charCodeAt();
        if (bytes === 0) {
          return true;
        } else if (bytes === 1 && char === 0) {
          return false;
        }
      }
      return true;
    }

    const isClearTextFile = (source) => {
      let stat = fs.lstatSync(path.resolve(source))
      if(stat.isFile()){
        let absFile = path.resolve(source)
        if (istextfile(absFile)) {
          return source
        } else {
          throw new Error('only clear text file can be encrypted')
        }
      }else{
        return source
      }
    }

    program.command('do')
      .description('Encrypted file')
      .argument('<source>', 'The file or folder that will be enctypted', isClearTextFile)
      .action(async (source) => {
        let password = prompt.hide('password: ')

        source = path.resolve(source)

        const encrypt = async (source , destination , password, salt) => {
          let stat = await fs.promises.lstat(source)
          if(stat.isFile()){
            // create chipher 
            const iv = await randomFill(new Uint8Array(16))
            let key = await scrypt(password, salt, 24)
            let cipher = crypto.createCipheriv(algorithm, key, iv)
            cipher.setEncoding('hex')
    
            // readin and writeout stream
            let writeoutFile = path.resolve(destination)
            let writeout = fs.createWriteStream(writeoutFile)
            let readin = fs.createReadStream(source)
    
            // First of all, write iv to destination file
            writeout.write(Buffer.from(iv).toString('hex') + '.')
    
            cipher.on('data', (chunk) => {
              writeout.write(chunk)
            });
            cipher.on('end', async () => {
              console.log(chalk.green.bold(`${writeoutFile} has been saved`))
            });
    
            readin.on('data', (chunk) => {
              cipher.write(chunk.toString('utf8'))
            })
    
            readin.on('end', () => {
              cipher.end()
            })
          }
        }

        let stat = await fs.promises.stat(source)
        if(stat.isFile()){
          let from = source
          let to = `${source}.enc`
          await encrypt(from, to, password, salt)
        }else{
          let files = await fs.promises.readdir(source)
          if(files.length > 0){
            let encryptedFolder = path.join(source, 'encrypted')
            await fs.promises.mkdir(encryptedFolder, { recursive: true })
            files.forEach( async (file)=>{
              let from = path.join(source, file)
              let stat = await fs.promises.lstat(from)
              if(stat.isFile()){
                if(istextfile(from)){
                  let to = path.join(encryptedFolder, `${file}.enc`)
                  await encrypt(from, to, password, salt)
                }
              }
            })
          }
        }
      })

    // UNDO
    const isEnc = (file) => {
      if (path.extname(file) !== '.enc') {
        return false
      } else {
        return true
      }
    }
    
    const isEncFile = (source) => {
      let stat = fs.lstatSync(path.resolve(source))
      if(stat.isFile()){
        if (isEnc(path.resolve(source)) === false) {
          throw new Error('This is not enc file')
        } else {
          return source
        }
      }else{
        return source
      }
    }

    program.command('undo')
      .description('Decrypted File')
      .argument('<source>', 'The file or folder that will be decrypted', isEncFile)
      .action(async (source) => {
        let password = prompt.hide('password: ')
        source = path.resolve(source)

        const decrypt = async (source, destination, password, salt) => {
          // Read encrypted data
          let data = (await fs.promises.readFile(source)).toString('utf8')
  
          // Compose decipher object
          let key = await scrypt(password, salt, 24)
          let IVandEnctypted = data.trim().split('.')
          let iv = new Uint8Array(Buffer.from(IVandEnctypted[0], 'hex'))
          let decipher = crypto.createDecipheriv(algorithm, key, iv)
          
          // Decrypt
          let encrypted = IVandEnctypted[1]
          let decrypted = ''
          decrypted = decipher.update(encrypted, 'hex', 'utf8')
          decrypted = decrypted + decipher.final('utf8')
  
          // Write to a file
          // let basename = path.basename(source).replace('.enc', '')
          let writeFile = path.resolve(destination)
          await fs.promises.writeFile(writeFile, decrypted)
  
          // output
          console.log(chalk.green.bold(`Decrypted to ${writeFile}`))
        }

        let stat = await fs.promises.lstat(source)
        if(stat.isFile()){
          let from = source
          let to = source.replace('.enc', '')
          await decrypt(from, to, password, salt)
        }else{
          let decryptedFolder = path.join(source, 'decrypted')
          await fs.promises.mkdir(decryptedFolder, { recursive: true })

          let files = await fs.promises.readdir(source)
          if(files.length > 0){
            files.forEach(async (file)=>{
              file = path.join(source, file)
              let stat = await fs.promises.lstat(file)
              if(stat.isFile()){
                if(isEnc(file)){
                  let from = file
                  let to = path.join(decryptedFolder, path.basename(file, '.enc'))
                  await decrypt(from, to , password, salt)
                }
              }
            })
          }
        }
      })

    await program.parseAsync(process.argv)

  } catch (error) {
    console.log(chalk.red.bold(error.message))
  }
}

main()