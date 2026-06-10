#!/usr/bin/env python3
# coding:utf-8
"""
Package utilitaires WebMapper.

Réexporte tous les symboles de l'ancien utils.py (rétrocompatibilité)
et expose les nouveaux modules (url_validator, session_manager).

Les imports existants dans le codebase :
    from utils import MarginStdout
    from utils import USER_AGENTS
    from utils import extract_form_fields
    from utils import obfuscate_payload
    from utils import calculate_similarity
continuent de fonctionner sans modification.
"""

#Rétrocompatibilité : réexport de tout l'ancien utils.py 
from utils._legacy import (
    # Layout terminal
    FONT_SIZE,
    MARGIN_X,
    PADDING_X,
    MarginStdin,
    MarginStdout,
    get_term_width,
    body_width,
    padded,
    centered,
    wrap_lines,
    print_wrapped,
    divider,
    print_section,
    # Outils de scan
    logger,
    USER_AGENTS,
    calculate_similarity,
    obfuscate_payload,
    extract_form_fields,
)

# Nouveaux modules
from utils.url_validator import URLValidator, validate_url
from utils.session_manager import SessionManager
