import pickle
import sys

class CipherStructure:

    def __init__(self, ciphered_text, key, initialization_vector, tag_sentence, signature):
        self.ciphered_text = ciphered_text
        self.key = key
        self.initialization_vector = initialization_vector
        self.tag_sentence = tag_sentence
        self.signature = signature

    def get_ciphered_text(self):
        return self.ciphered_text

    def get_key(self):
        return self.key

    def get_initialization_vector(self):
        return self.initialization_vector

    def get_tag_sentence(self):
        return self.tag_sentence

    def get_signature(self):
        return self.signature

    def dump_to_file(self, output_file):
        pickle.dump(self, output_file)

    @staticmethod
    def load_from_file(input_file):
        try:
            tmp = pickle.load(input_file)
            if isinstance(tmp, CipherStructure):
                return tmp
        except:
            print ">> ERROR corrupted ciphered file "
            sys.exit()
