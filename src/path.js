import File from './file'

export default class Path {
  constructor (client, data) {
    this.client = client
    this.original = data

    this.id = data.id
    this.parentId = data.parent_id
    this.path = data.path
    this.mktime = data.mktime ? new Date(data.mktime * 1000) : null
    this.mdtime = data.mdtime ? new Date(data.mdtime * 1000) : null
    this.checksum = data.checksum
    this.files = data.files.map(file => new File(this.client, file))
    this.paths = data.paths.map(path => new Path(this.client, path))
  }
}
