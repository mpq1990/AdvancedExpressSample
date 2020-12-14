const sharp = require('sharp');
const uuid = require('uuid');
const util = require('util');
const path = require('path');
const fs = require('fs');

const fsunlink = util.promisify(fs.unlink);

class AvatarService {
  constructor(directory) {
    this.directory = directory;
  }

  async store(buffer) {
    const filename = AvatarService.filename();
    const filepath = this.filepath(filename);

    await sharp(buffer)
      .resize(300, 300, {
        fit: sharp.fit.inside,
        withoutEnlargement: true,
      })
      .toFile(filepath);

    return filename;
  }

  async thumbnail(filename) {
    return sharp(this.filepath(filename)).resize(50, 50).toBuffer();
  }

  async delete(filename) {
    return fsunlink(this.filepath(filename));
  }

  static filename() {
    return `${uuid()}.png`;
  }

  filepath(filename) {
    return path.resolve(`${this.directory}/${filename}`);
  }
}

module.exports = AvatarService;
