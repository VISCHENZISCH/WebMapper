#!/usr/bin/env python3
# coding:utf-8
import json

def generate(data, filepath):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
