export function uint8ToString (arr) {
  let result = ''
  for (let i = 0; i < arr.length; i++) {
    result += String.fromCharCode(arr[i])
  }
  return result
}

export function stringToUint8 (str) {
  let result = new Uint8Array(str.length)
  for (let i = 0; i < str.length; i++) {
    result[i] = str.charCodeAt(i)
  }
  return result
}

/**
 * Creates a new Uint8Array based on two different ArrayBuffers
 *
 * @private
 * @param {ArrayBuffer} buffer1 The first buffer.
 * @param {ArrayBuffer} buffer2 The second buffer.
 * @return {ArrayBuffer} The new ArrayBuffer created out of the two.
 */
export function appendBuffer (buffer1, buffer2) {
  var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength)
  tmp.set(new Uint8Array(buffer1), 0)
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength)
  return tmp.buffer
}

export function hex (buffer) {
  var hexCodes = []
  var view = new DataView(buffer)
  for (var i = 0; i < view.byteLength; i += 4) {
    // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
    var value = view.getUint32(i)
    // toString(16) will give the hex representation of the number without padding
    var stringValue = value.toString(16)
    // We use concatenation and slice for padding
    var padding = '00000000'
    var paddedValue = (padding + stringValue).slice(-padding.length)
    hexCodes.push(paddedValue)
  }

  // Join all the hex strings into one
  return hexCodes.join('')
}
