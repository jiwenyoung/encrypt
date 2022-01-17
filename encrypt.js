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

    const isClearTextFile = (file) => {
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
      let absFile = path.resolve(file)
      if (istextfile(absFile)) {
        return file
      } else {
        throw new Error('only clear text file can be encrypted')
      }
    }

    program.command('do')
      .description('Encrypted file')
      .argument('<file>', 'The file that will be enctypted', isClearTextFile)
      .action(async (file) => {
        let password = prompt.hide('password: ')

        // create chipher 
        const iv = await randomFill(new Uint8Array(16))
        let key = await scrypt(password, salt, 24)
        let cipher = crypto.createCipheriv(algorithm, key, iv)
        cipher.setEncoding('hex')

        // readin and writeout stream
        let writeoutFile = path.resolve(`.\\${file}.enc`)
        let readin = fs.createReadStream(path.resolve(file))
        let writeout = fs.createWriteStream(writeoutFile)

        // First of all, write iv to destination file
        writeout.write(Buffer.from(iv).toString('hex') + '.')

        cipher.on('data', (chunk) => {
          writeout.write(chunk)
        });
        cipher.on('end', async () => {
          console.log(chalk.green.bold(`${writeoutFile} has been created`))
        });

        readin.on('data', (chunk) => {
          cipher.write(chunk.toString('utf8'))
        })

        readin.on('end', () => {
          cipher.end()
        })
      })

    const isEncFile = (file) => {
      if (path.extname(file) !== '.enc') {
        throw new Error('This is not enc file')
      } else {
        return file
      }
    }

    program.command('undo')
      .description('Decrypted File')
      .argument('<file>', 'The file that will be decrypted', isEncFile)
      .action(async (file) => {
        let password = prompt.hide('password: ')

        // Read encrypted data
        let data = (await fs.promises.readFile(file)).toString('utf8')

        // Compose decipher object
        let key = await scrypt(password, salt, 24)
        let IVandEnctypted = data.trim().split('.')
        let iv = new Uint8Array(Buffer.from(IVandEnctypted[0], 'hex'))
        let encrypted = IVandEnctypted[1]
        let decipher = crypto.createDecipheriv(algorithm, key, iv)

        // Decrypt
        let decrypted = ''
        decrypted = decipher.update(encrypted, 'hex', 'utf8')
        decrypted = decrypted + decipher.final('utf8')

        // Write to a file
        let basename = path.basename(file).replace('.enc', '')
        let writeFile = path.resolve(`.\\${basename}`)
        await fs.promises.writeFile(writeFile, decrypted)

        // output
        console.log(chalk.green.bold(`Decrypted to ${writeFile}`))
      })
    await program.parseAsync(process.argv)

  } catch (error) {
    console.log(chalk.red.bold(error.message))
  }
}

main()