import base64
import sys

import random

import requests
from requests.adapters import HTTPAdapter, PoolManager

""" --------------------------- Enums section ------------------------------ """


class CMD:
  WHOISHERE = 1
  IAMHERE = 2
  GETSTATUS = 3
  STATUS = 4
  SETSTATUS = 5
  TICK = 6


class DT:
  SmartHub = 1
  EnvSensor = 2
  Switch = 3
  Lamp = 4
  Socket = 5
  Clock = 6


""" --------------------- Custom HTTP client section ----------------------- """


class SourcePortAdapter(HTTPAdapter):
  """
  Custom transport adapter that allows us to set
  the source port for all outgoing requests.

  source: https://stackoverflow.com/questions/47202790/python-requests-how-to-specify-port-for-outgoing-traffic
  """

  def __init__(self, port, *args, **kwargs):
    self._source_port = port
    super(SourcePortAdapter, self).__init__(*args, **kwargs)

  def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
    self.poolmanager = PoolManager(num_pools=connections,
                                   maxsize=maxsize,
                                   block=block,
                                   source_address=('', self._source_port))


class Client:
  """ Client for sending requests """
  session: requests.Session

  def __init__(self, port: int = 54321) -> None:
    self.session = requests.Session()

    self.session.mount('http://', SourcePortAdapter(port))
    self.session.mount('https://', SourcePortAdapter(port))

  def send_request(self, url: str, data) -> requests.Response:
    return self.session.post(url, data)


""" --------------------- Encoders | Decoders section ---------------------- """


class EncodingManager:
  """
  Encoding manager for b64, uleb128.
  """

  @staticmethod
  def b64_encode(val: bytes) -> bytes:
    return base64.urlsafe_b64encode(val).rstrip(b'=')

  @staticmethod
  def uleb128_encode(val: int) -> bytes:
    if val < 0:
      raise ValueError('Encoding value must be >= 0')

    result = bytearray()

    while True:
      byte = val & 0x7f
      val >>= 7

      if val == 0:
        result.append(byte)
        break

      result.append(byte | 0x80)

    return result

  @staticmethod
  def encode_string(val: str) -> bytes:
    return bytes([len(val)] + [ord(ch) for ch in val])


class DecodingManager:
  """
  Decoding manager for b64, uleb128.
  """

  @staticmethod
  def uleb128_decode(val: bytes) -> int:
    result = 0

    for i, e in enumerate(val):
      result += (e & 0x7f) << (i * 7)

    return result

  @staticmethod
  def b64_decode(val: bytes) -> bytes:
    return base64.urlsafe_b64decode(val + b'=' * (4 - len(val) % 4))


class CRC8Encoder:
  """
  CRC8 checksum encoding manager.
  """
  table: list[int]

  def __init__(self) -> None:
    self.table = self.build_table()

  @staticmethod
  def build_table() -> list[int]:
    table = []

    for dividend in range(256):
      current_byte = dividend

      for _ in range(8):
        if current_byte & 0x80:
          current_byte = (current_byte << 1) ^ 0x1D
        else:
          current_byte <<= 1

      table.append(current_byte & 255)

    return table

  def compute(self, val: bytes) -> int:
    checksum = 0

    for byte in val:
      checksum = self.table[byte ^ checksum]

    return checksum


""" ----------------------- Encoding packet section ------------------------ """


def encode_cmd_body(cmd: int, kwargs: dict) -> bytearray:
  result = bytearray()

  if cmd in (CMD.WHOISHERE, CMD.IAMHERE):
    result.append(len(kwargs['dev_name']))
    result.extend(kwargs['dev_name'].encode())

  elif cmd == CMD.SETSTATUS:
    result.append(kwargs['value'])

  return result


def encode_payload(src: int, dst: int, serial: int, dev_type: int, cmd: int, kwargs: dict) -> bytearray:
  return bytearray(
    i for val in (src, dst, serial) for i in EncodingManager.uleb128_encode(val)
  ) + bytearray(
    [dev_type, cmd, *encode_cmd_body(cmd, kwargs)]
  )


def encode_packet(src: int, dst: int, serial: int, dev_type: int, cmd: int, **kwargs) -> bytes:
  payload = encode_payload(src, dst, serial, dev_type, cmd, kwargs)
  check_summ = crc8_encoder.compute(payload)

  return bytes([len(payload)] + list(payload) + [check_summ])


""" ----------------------- Decoding packet section ------------------------ """


def decode_cmd_body(cmd_body: bytes | bytearray, dev_type: int, cmd: int) -> dict:
  data = {}

  if dev_type in (DT.EnvSensor, DT.Lamp, DT.Socket):
    if cmd in (CMD.WHOISHERE, CMD.IAMHERE):
      data['dev_name'] = cmd_body[1:].decode('ascii')

    if dev_type == DT.EnvSensor and cmd == CMD.WHOISHERE:
      length = cmd_body[0]
      dev_props = {}
      i = length + 1
      info = cmd_body[i]
      mask = [index for index, sensor in enumerate(bin(info)[2:][::-1]) if sensor == '1']
      i += 1
      array_len = cmd_body[i]
      triggers = []

      for _ in range(array_len):
        new_trigger = {}
        op = cmd_body[i]
        op_value = op & 1
        new_trigger['send_value'] = op_value
        new_trigger['sign'] = 'more' if op & 2 else 'less'
        sensor_num = op >> 2
        new_trigger['sensor_num'] = mask[sensor_num]

        bin_value = bytearray()
        i += 1

        while cmd_body[i] & 0x80:
          bin_value.append(cmd_body[i])
          i += 1

        bin_value.append(cmd_body[i])
        new_trigger['value'] = DecodingManager.uleb128_decode(bin_value)
        i += 1
        name_len = cmd_body[i]
        new_trigger['name'] = cmd_body[i + 1:i + 1 + name_len].decode('ascii')
        i += 1 + name_len
        triggers.append(new_trigger)

      dev_props['triggers'] = triggers
      data['dev_props'] = dev_props

    elif (dev_type == DT.EnvSensor and cmd == CMD.STATUS) \
            or (dev_type in (DT.Lamp, DT.Socket) and cmd == CMD.STATUS):
      data['value'] = cmd_body[0]

  elif dev_type == DT.Clock:
    if cmd in (CMD.WHOISHERE, CMD.IAMHERE):
      data['dev_name'] = cmd_body[1:].decode('ascii')
    elif cmd == CMD.TICK:
      timestamp = DecodingManager.uleb128_decode(cmd_body)
      data['timestamp'] = timestamp

  elif dev_type == DT.Switch:
    if cmd in (CMD.WHOISHERE, CMD.IAMHERE):
      length = cmd_body[0]
      data['dev_name'] = cmd_body[1:length + 1].decode('ascii')
      i = length + 2
      dev_names = []

      for _ in range(cmd_body[i - 1]):
        length = cmd_body[i]
        new_name = cmd_body[i + 1:i + 1 + length].decode('ascii')
        dev_names.append(new_name)
        i += length + 1

      data['dev_props'] = {'dev_names': dev_names}

    elif cmd in (CMD.STATUS, CMD.SETSTATUS):
      data['value'] = cmd_body[0]

  return data


def decode_payload(payload: bytes) -> dict:
  i = 0

  def decode_field() -> int:
    nonlocal i
    field = bytearray()

    while payload[i] & 0x80:
      field.append(payload[i])
      i += 1

    field.append(payload[i])
    i += 1

    return DecodingManager.uleb128_decode(field)

  return {
    'src': decode_field(),
    'dst': decode_field(),
    'serial': decode_field(),
    'dev_type': payload[i],
    'cmd': payload[i + 1],
    'cmd_body': decode_cmd_body(payload[i + 2:], payload[i], payload[i + 1])
  }


def decode_packet(packet: bytes) -> dict:
  length = packet[0]

  return {
    'length': length,
    'payload': decode_payload(packet[1:1 + length]),
    'crc8': packet[length + 1],
    'real_crc8': crc8_encoder.compute(packet[1:1 + length])
  }


def decode_packets(packets: bytes) -> list[dict]:
  decoded_packets, i = [], 0

  while i < len(packets):
    length = packets[i] + 2
    decoded_packets.append(decode_packet(packets[i:i + length]))
    i += length

  return decoded_packets


""" -------------------------- Smart hub section --------------------------- """


class SmartHouseHub:
  url: str
  src: int
  serial: int

  def __init__(self, url: str, src: int) -> None:
    self.url = url
    self.src = src
    self.serial = 1

  def send_packet(self, packet: bytes) -> requests.Response:
    """ Send encoded request to server """
    try:
      response = client.send_request(self.url,
                                     EncodingManager.b64_encode(packet))
      assert response.status_code == 200 or response.status_code == 204
      self.serial += 1
    except (requests.RequestException, AssertionError) as e:
      sys.exit(99)

    if response.status_code == 204:
      sys.exit(0)

    return response

  def start_managing(self) -> None:
    response = self.send_packet(encode_packet(self.src, 0x3fff, self.serial,
                                              DT.SmartHub, CMD.WHOISHERE,
                                              dev_name="SmartHouseHub"))

    packets = decode_packets(DecodingManager.b64_decode(response.content))

    start_time = packets[0]['payload']['cmd_body']['timestamp']
    current_time = start_time

    devices, name_address = {}, {}

    while True:
      packets_to_send = bytearray()
      addresses = list(name_address.keys())

      if len(packets) > 0 and packets[0]['payload']['cmd'] == CMD.TICK \
              and packets[0]['crc8'] == packets[0]['real_crc8']:
        current_time = packets[0]['payload']['cmd_body']['timestamp']
        packets.pop(0)
      else:
        current_time = start_time if 'start_time' in locals() else 0

      for address in addresses:
        dev_name = name_address[address]

        if current_time - devices[dev_name].get('get_time', current_time) > 300:
          name_address.pop(address)
          devices.pop(dev_name)

      for packet in packets:
        if packet['crc8'] != packet['real_crc8']:
          continue

        payload = packet['payload']
        payload_cmd = payload['cmd']
        cmd_body = payload['cmd_body']
        address = payload['src']
        dev_type = payload['dev_type']

        if payload_cmd in (CMD.IAMHERE, CMD.WHOISHERE):
          if payload_cmd == CMD.IAMHERE and current_time - start_time > 300:
            continue

          dev_name = cmd_body['dev_name']
          name_address[address] = dev_name

          devices[dev_name] = {'address': address, 'type': dev_type}

          if dev_type in (DT.EnvSensor, DT.Switch):
            devices[dev_name]['props'] = cmd_body['dev_props']

          if dev_type != DT.Clock and payload_cmd == CMD.IAMHERE:
            devices[dev_name]['get_time'] = current_time

            packets_to_send.extend(encode_packet(self.src, address, self.serial,
                                                 dev_type, CMD.GETSTATUS))

          if payload_cmd == CMD.WHOISHERE:
            packets_to_send.extend(encode_packet(self.src, 0x3fff, self.serial,
                                                 DT.SmartHub, CMD.IAMHERE,
                                                 dev_name="HUB01"))

        elif payload_cmd == CMD.STATUS:
          if address not in name_address:
            continue

          dev_name = name_address[address]
          devices[dev_name].pop('get_time', None)
          devices[dev_name]['status'] = cmd_body['values'] if dev_type == DT.EnvSensor else cmd_body['value']

          if dev_type == DT.EnvSensor:
            for trigger in devices[dev_name]['props']['triggers']:
              trigger_val = cmd_body['values'][trigger['sensor_num']]
              if (trigger['sign'] == 'less' and trigger_val < trigger['value']) or \
                      (trigger['sign'] == 'more' and trigger_val > trigger['value']):
                send_name = trigger['name']
                send_dev = devices[send_name]
                send_dev['get_time'] = current_time

                packets_to_send.extend(encode_packet(self.src, send_dev['address'], self.serial,
                                                     send_dev['type'], CMD.SETSTATUS,
                                                     value=trigger['send_value']))

          elif dev_type == DT.Switch:
            for send_name in devices[dev_name]['props']['dev_names']:
              send_dev = devices.get(send_name)
              if send_dev:
                send_dev['get_time'] = current_time

                packets_to_send.extend(encode_packet(self.src, send_dev['address'], self.serial,
                                                     send_dev['type'], CMD.SETSTATUS,
                                                     value=devices[dev_name]['status']))

      response = self.send_packet(packets_to_send)

      try:
        packets = decode_packets(DecodingManager.b64_decode(response.content))
      except IndexError:
        packets = bytearray()
        continue


client = Client(port=random.randint(100, 54324))
crc8_encoder = CRC8Encoder()

if __name__ == "__main__":
  hub = SmartHouseHub(url=sys.argv[1],
                      src=int(sys.argv[2], 16))

  hub.start_managing()
