import textwrap
from fpdf import FPDF

def create_pdf_report(title, data_dict, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", 'B', 16)
    
    def clean_text(text):
        text = str(text)
        replacements = {
            'ą':'a', 'ć':'c', 'ę':'e', 'ł':'l', 'ń':'n', 'ó':'o', 'ś':'s', 'ź':'z', 'ż':'z',
            'Ą':'A', 'Ć':'C', 'Ę':'E', 'Ł':'L', 'Ń':'N', 'Ó':'O', 'Ś':'S', 'Ź':'Z', 'Ż':'Z',
            '⚠️':'[ZAGROZENIE]', '✅':'[CZYSTY]', '🔍':'[INFO]'
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        return text.encode('latin-1', 'ignore').decode('latin-1')

    pdf.cell(0, 10, txt=clean_text(title), ln=True, align='C')
    pdf.ln(5)
    
    for section_title, df in data_dict.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, txt=clean_text(section_title), ln=True)
        pdf.set_font("Arial", size=8)
        
        for index, row in df.iterrows():
            row_text = " | ".join([f"{col}: {clean_text(val)}" for col, val in row.items()])
            
            wrapped_text = textwrap.fill(row_text, width=110)
            for line in wrapped_text.split('\n'):
                pdf.cell(0, 5, txt=line, ln=True)
            pdf.ln(2)
            
        pdf.ln(5)
        
    pdf.output(filename)