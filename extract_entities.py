import sys
import json
import spacy
from functools import lru_cache

# Set UTF-8 encoding for input and output
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')

nlp = spacy.load('en_core_web_md')

@lru_cache(maxsize=100)
def process_text(text):
    return nlp(text)

def extract_entities(text):
    doc = process_text(text)
    entities = [{"text": ent.text, "label": ent.label_} for ent in doc.ents]
    return entities

if __name__ == '__main__':
    input_text = sys.stdin.read()  # Read text from stdin
    entities = extract_entities(input_text)
    json.dump(entities, sys.stdout, ensure_ascii=False)  # Output results in JSON format