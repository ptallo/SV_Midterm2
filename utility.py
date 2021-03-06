one_time_pad = None
escape_sequence = None
random_seed = None

def encrypt_or_decrypt(message):
    '''
    Encrypts or decrypts the message with a one time pad.
    :param message: string to be encrypted or decrypted
    :return: message encrypted with a one time pad
    '''
    if one_time_pad is None:
        get_one_time_pad()
    if len(message) > len(one_time_pad):
        raise Exception("Message is too long")
    return xor_two_str(message, one_time_pad[0:len(message)])


def xor_two_str(s1, s2):
    """
    Source for below function: https://stackoverflow.com/questions/36242887/how-to-xor-two-strings-in-python/36242949
    With small modifications
    """
    xored = []
    for i in range(max(len(s1), len(s2))):
        xored_value = ord(s1[i % len(s1)]) ^ ord(s2[i % len(s2)])
        xored.append(chr(xored_value))
    return ''.join(xored)


def get_escape_sequence():
    """
    Gets the escape sequence used for stop function on sniffer
    :return: escape sequence
    """
    global escape_sequence
    if escape_sequence is None:
        f = open("input/escape_character.txt", "r")
        lines = f.readlines()
        escape_sequence = int(lines[0])
        f.close()
    return escape_sequence


def get_one_time_pad():
    # For demonstration purposes, we use the same one-time pad (stored in a file) for all executions
    # A real attacker would only run this program once, and write a new program with a new one-time pad 
    # for subsequent attacks
    global one_time_pad
    if one_time_pad is None:
        f = open("input/one_time_pad.txt", "r")
        lines = f.readlines()
        one_time_pad = lines[0]
        f.close()
    return one_time_pad


def get_random_seed():
    # For demonstration purposes, we use the same random seed (stored in a file) for all executions
    # A real attacker would only run this program once, and write a new program with a new random seed 
    # for subsequent attacks
    global random_seed
    if random_seed is None:
        f = open("input/random_seed.txt", "r")
        lines = f.readlines()
        random_seed = int(lines[0])
        f.close()
    return random_seed
