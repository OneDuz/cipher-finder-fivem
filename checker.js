const fs = require('fs');
const path = require('path');
const readline = require('readline');

const signatures = [
    { id: 1, pattern: Buffer.from('68656c70436f6465', 'hex').toString(), description: 'helpCode' },
    { id: 2, pattern: Buffer.from('617373657274', 'hex').toString(), description: 'assert' },
    { id: 3, pattern: Buffer.from('506572666f726d4874747052657175657374', 'hex').toString(), description: 'PerformHttpRequest' },
    { id: 4, pattern: Buffer.from('76325f', 'hex').toString(), description: 'Hexadecimal v2_' },
    { id: 5, pattern: Buffer.from('2e706870', 'hex').toString(), description: 'Hexadecimal .php' },
    { id: 6, pattern: Buffer.from('68747470733a2f2f6e6574636174616c797a652e6f72672f76325f2f7374616765332e7068703f746f3d3371326635', 'hex').toString(), description: 'Suspicious URL' },
    { id: 6, pattern: Buffer.from('6874747073', 'hex').toString(), description: 'https URL' },
    { id: 6, pattern: Buffer.from('68747470', 'hex').toString(), description: 'http URL' },
];

const fileExtensionsToScan = ['lua'];

const currentDir = process.cwd();
const logFile = path.join(currentDir, 'scan_log.txt');
const flaggedLogFile = path.join(currentDir, 'flagged_log.txt');

function promptForDirectory() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question('Enter the directory to scan: ', (answer) => {
            rl.close();
            resolve(answer.trim());
        });
    });
}

function isDirectory(dir) {
    try {
        return fs.lstatSync(dir).isDirectory();
    } catch (err) {
        log(`Error: Failed to access directory ${dir}`);
        return false;
    }
}

function getFileExtension(filename) {
    return path.extname(filename).slice(1);
}

function readDirectory(dir) {
    try {
        return fs.readdirSync(dir);
    } catch (err) {
        log(`Error: Failed to read directory ${dir}`);
        return [];
    }
}

function decodeHexStrings(content) {
    return content.replace(/\\x([0-9A-Fa-f]{2})/g, (match, p1) => {
        return String.fromCharCode(parseInt(p1, 16));
    });
}

function containsSignature(content, fullPath) {
    let found = false;
    const decodedContent = decodeHexStrings(content);
    const lines = decodedContent.split('\n');
    const flaggedLines = [];

    lines.forEach((line, lineNumber) => {
        signatures.forEach((signature) => {
            if (line.includes(signature.pattern)) {
                found = true;
                flaggedLines.push({ line: lineNumber + 1, content: line.trim(), description: signature.description });
            }
        });

        if (/(_G|loadstring)/.test(line)) {
            found = true;
            flaggedLines.push({ line: lineNumber + 1, content: line.trim(), description: 'Obfuscation pattern' });
        }
    });

    if (found) {
        logFlaggedFile(fullPath, flaggedLines);
    }

    return found;
}

function log(message) {
    console.log(message);
    fs.appendFileSync(logFile, `${new Date().toISOString()} - ${message}\n`);
}

function logFlaggedFile(filePath, flaggedLines) {
    const relativePath = path.relative(currentDir, filePath);
    const dirName = path.dirname(relativePath);
    const fileName = path.basename(filePath);

    const header = `${dirName}/\n  ${fileName}`;
    const logLines = flaggedLines.map(fl => `    - Line ${fl.line}: ${fl.content} [${fl.description}]`).join('\n');

    const logMessage = `${header}\n${logLines}\n\n`;

    console.log(logMessage);
    fs.appendFileSync(flaggedLogFile, `${new Date().toISOString()} - ${logMessage}`);
}

function scanDirectory(resourceDir, flaggedDirs = {}) {
    const files = readDirectory(resourceDir);

    files.forEach((file) => {
        const fullPath = path.join(resourceDir, file);
        if (isDirectory(fullPath)) {
            scanDirectory(fullPath, flaggedDirs);
        } else {
            const fileExt = getFileExtension(file);
            if (fileExtensionsToScan.includes(fileExt)) {
                log(`Scanning file: ${fullPath}`);
                const content = fs.readFileSync(fullPath, 'utf-8');
                if (containsSignature(content, fullPath)) {
                    const dir = path.dirname(fullPath);
                    if (!flaggedDirs[dir]) {
                        flaggedDirs[dir] = [];
                    }
                    flaggedDirs[dir].push(fullPath);
                }
            } else {
                log(`Skipping file: ${fullPath} (unsupported extension)`);
            }
        }
    });

    return flaggedDirs;
}

function cloneFlaggedFiles(flaggedDirs, cloneDir) {
    Object.keys(flaggedDirs).forEach((dir) => {
        const files = flaggedDirs[dir];
        files.forEach((filePath) => {
            const relativePath = path.relative(currentDir, filePath);
            const destPath = path.join(cloneDir, relativePath);
            const destDir = path.dirname(destPath);

            fs.mkdirSync(destDir, { recursive: true });
            fs.copyFileSync(filePath, destPath);

            log(`Cloned flagged file to: ${destPath}`);
        });
    });
}

async function main() {
    const resourceDir = await promptForDirectory();
    if (!isDirectory(resourceDir)) {
        log('Error: The specified directory does not exist or is not a directory.');
        return;
    }

    log('Starting scan of resources...');
    const flaggedDirs = scanDirectory(resourceDir);

    if (Object.keys(flaggedDirs).length > 0) {
        const cloneDir = path.join(currentDir, 'flagged_files_clone');
        cloneFlaggedFiles(flaggedDirs, cloneDir);
        log(`Cloning completed. Flagged files have been copied to: ${cloneDir}`);
    } else {
        log('No flagged files found.');
    }

    log('Stopped scanning.');
}

main();
