const puppeteer = require('puppeteer')

const FLAG = process.env.FLAG || 'RS{meow_meow_fake_flag}'
const SITE = process.env.SITE || 'http://localhost:3031'
const URL_RE = /^https?:\/\/.+/

const TIMEOUT = 120_000

async function doVisit(url) {
    console.log('launching browser');
    const browser = await puppeteer.launch({
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
        headless: 'new',
        args: (process.env.BROWSER_FLAGS || '').split(',').filter(Boolean),
    });

    try {
        const setup = await browser.newPage()
        console.log(`admin bot visiting ${SITE}`)
        await setup.goto(SITE, { waitUntil: 'networkidle0', timeout: TIMEOUT })

        await setup.type('#note-input', FLAG)
        await setup.click('.btn-primary')
        await setup.waitForNetworkIdle({ timeout: TIMEOUT })

        await setup.close()

        const page = await browser.newPage()
        console.log(`admin bot visiting ${url}`)
        await page.goto(url, { waitUntil: 'networkidle0', timeout: TIMEOUT })

        await new Promise((r) => setTimeout(r, TIMEOUT))

        console.log('admin bot done')
    } catch (err) {
        console.error(`admin bot error: ${err.message}`)
    } finally {
        await browser.close()
    }
}

function visit(url) {
    if (!URL_RE.test(url)) {
        throw new Error('invalid url')
    }
    doVisit(url)
}

module.exports = { visit }