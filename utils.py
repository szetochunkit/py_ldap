import configparser
import base64

def decode_str( encode_str ):
    decode_res = base64.b64decode(encode_str).decode("utf-8")
    return decode_res

def get_config_value(file_path, section, key):
    """
    读取配置文件中的指定键值。
    :param file_path: 配置文件路径
    :param section: 配置文件中的节名称
    :param key: 配置文件中的键名称
    :return: 对应的键值
    """
    # 创建 ConfigParser 对象
    config = configparser.ConfigParser()
    # 读取配置文件
    config.read(file_path)
    # 检查是否存在指定的节
    if section not in config:
        raise Exception(f"Missing section '{section}' in configuration file.")
    # 检查是否存在指定的键
    if key not in config[section]:
        raise Exception(f"Missing key '{key}' in section '{section}' in configuration file.")
    # 获取并返回指定的键值
    return config.get(section, key)





