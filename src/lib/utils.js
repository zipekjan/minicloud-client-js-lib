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
