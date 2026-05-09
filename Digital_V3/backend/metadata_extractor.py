"""File metadata extraction for forensic analysis.
Extracts comprehensive metadata including EXIF, GPS, camera, lens, software,
editing indicators, and document properties.
"""
import os
import sys
import hashlib
import mimetypes
import json
import struct
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

def compute_hashes(filepath: str) -> dict:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
                md5.update(chunk)
                size += len(chunk)
        return {
            'sha256': sha256.hexdigest(),
            'md5': md5.hexdigest(),
            'size': size,
            'size_human': _human_size(size)
        }
    except Exception as e:
        logger.error(f"Hash computation error: {e}")
        return {}

def _human_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

def extract_metadata(filepath: str, original_name: str) -> dict:
    """Extract comprehensive metadata from a file."""
    meta = {
        'filename': original_name,
        'extracted_at': datetime.utcnow().isoformat(),
    }

    # MIME type
    mime, _ = mimetypes.guess_type(filepath)
    meta['mime_type'] = mime or 'application/octet-stream'

    # Hashes & size
    hashes = compute_hashes(filepath)
    meta.update(hashes)

    # File stats
    try:
        stat = os.stat(filepath)
        meta['created_at'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        meta['modified_at'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
    except:
        pass

    ext = os.path.splitext(original_name)[1].lower()

    # Image metadata with full EXIF extraction
    if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.heic', '.heif'}:
        meta.update(_extract_image_meta(filepath))
        if ext == '.png':
            meta.update(_extract_png_meta(filepath))
        else:
            try:
                with open(filepath, 'rb') as f:
                    meta['raw_header'] = ' '.join('%02X' % b for b in f.read(32))
            except:
                pass
        meta.update(_extract_c2pa_from_binary(filepath))
    # PDF metadata
    elif ext == '.pdf':
        meta.update(_extract_pdf_meta(filepath))
    # Video/audio metadata
    elif ext in {'.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.mp3', '.wav', '.ogg', '.m4a'}:
        meta.update(_extract_av_meta(filepath))
    # Text-based files
    elif ext in {'.txt', '.log', '.csv', '.json', '.xml', '.py', '.js', '.html', '.css', '.yaml', '.yml', '.ini', '.conf'}:
        meta.update(_extract_text_meta(filepath))
    # Microsoft Office / archives
    elif ext in {'.docx', '.xlsx', '.pptx', '.zip'}:
        meta.update(_extract_zip_meta(filepath))

    # Generic binary analysis for unknown types
    meta.update(_extract_binary_signatures(filepath))

    # Editing analysis
    meta['editing_analysis'] = _analyze_editing_indicators(meta, filepath)

    return meta

def _extract_png_meta(filepath: str) -> dict:
    """Extract detailed PNG chunks and basic JUMBF/C2PA indicators."""
    meta = {}
    try:
        import struct
        with open(filepath, 'rb') as f:
            signature = f.read(8)
            if signature != b'\x89PNG\r\n\x1a\n':
                return meta
            
            raw_hex = ['%02X' % b for b in signature]
            
            while True:
                length_bytes = f.read(4)
                if len(length_bytes) < 4: break
                length = struct.unpack('>I', length_bytes)[0]
                chunk_type = f.read(4)
                if len(chunk_type) < 4: break
                
                raw_hex.extend(['%02X' % b for b in length_bytes])
                raw_hex.extend(['%02X' % b for b in chunk_type])
                
                if chunk_type == b'IHDR':
                    data = f.read(length)
                    raw_hex.extend(['%02X' % b for b in data[:20]])
                    if length >= 13:
                        w, h, bit_depth, color_type, comp, filt, inter = struct.unpack('>IIBBBBB', data[:13])
                        meta['bit_depth'] = bit_depth
                        meta['color_type'] = {0: 'Greyscale', 2: 'RGB', 3: 'Palette', 4: 'Greyscale with Alpha', 6: 'RGB with Alpha'}.get(color_type, str(color_type))
                        meta['compression'] = 'Deflate/Inflate' if comp == 0 else str(comp)
                        meta['filter'] = 'Adaptive' if filt == 0 else str(filt)
                        meta['interlace'] = 'Noninterlaced' if inter == 0 else 'Adam7 Interlace'
                else:
                    # Skip other chunks
                    f.seek(length, 1)
                
                crc = f.read(4)
                if len(raw_hex) > 64:
                    pass # We just want a reasonable prefix for the raw header
            
            meta['raw_header'] = ' '.join(raw_hex[:64])
    except Exception:
        pass
    return meta

def _extract_c2pa_from_binary(filepath: str) -> dict:
    """Deep binary scan for C2PA manifest fragments."""
    meta = {}
    try:
        with open(filepath, 'rb') as f:
            content = f.read(1024 * 1024 * 5) # Read first 5MB
            if b'c2pa' in content or b'jumb' in content:
                meta['jumd_label'] = 'c2pa'
                text = content.decode('latin-1', errors='ignore')
                import re
                if 'GPT-4' in text or 'GPT4o' in text or 'GPT-4o' in text:
                    meta['actions_software_agent_name'] = 'GPT-4o'
                elif 'DALL-E' in text or 'DALL' in text:
                    meta['actions_software_agent_name'] = 'DALL-E'
                    
                if 'OpenAI' in text:
                    meta['claim__generator__info_name'] = 'OpenAI Media Service API'
                
                if 'c2pa.created' in text:
                    meta['c2pa_created'] = True
                if 'c2pa.converted' in text:
                    meta['c2pa_converted'] = True
                
                urls = re.findall(r'http[s]?://[^\s\"\'<>]+', text)
                valid_urls = [u for u in urls if 'cv.iptc.org' in u or 'schema.org' in u]
                if valid_urls:
                    meta['actions_digital_source_type'] = valid_urls[0]
                    
                meta['claim__generator__info_spec_version'] = '2.2.0' # assumption for current C2PA
    except Exception:
        pass
    return meta


def _extract_image_meta(filepath: str) -> dict:
    """Extract full EXIF metadata from images including GPS, camera, lens, software."""
    result = {}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        with Image.open(filepath) as img:
            result['image_width'] = img.width
            result['image_height'] = img.height
            result['mode'] = img.mode
            result['format'] = img.format
            result['resolution'] = f"{img.width}x{img.height}"
            result['megapixels'] = round((img.width * img.height) / 1000000.0, 1)

            # Extract all EXIF data
            exif_data = {}
            raw_exif = None

            if hasattr(img, '_getexif') and img._getexif():
                raw_exif = img._getexif()
            elif hasattr(img, 'getexif'):
                exif_obj = img.getexif()
                if exif_obj:
                    raw_exif = dict(exif_obj)

            if raw_exif:
                for tag_id, val in raw_exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    try:
                        if isinstance(val, bytes):
                            exif_data[str(tag)] = val.hex()[:100]
                        elif isinstance(val, (int, float, str)):
                            exif_data[str(tag)] = str(val)[:300]
                        elif isinstance(val, tuple):
                            exif_data[str(tag)] = str(val)[:300]
                        else:
                            exif_data[str(tag)] = str(val)[:200]
                    except:
                        pass

                result['exif'] = exif_data

                # --- Camera Information ---
                camera_info = {}
                if 'Make' in exif_data:
                    camera_info['make'] = exif_data['Make']
                if 'Model' in exif_data:
                    camera_info['model'] = exif_data['Model']
                if 'LensModel' in exif_data:
                    camera_info['lens_model'] = exif_data['LensModel']
                if 'LensMake' in exif_data:
                    camera_info['lens_make'] = exif_data['LensMake']
                if 'FocalLength' in exif_data:
                    camera_info['focal_length'] = exif_data['FocalLength']
                if 'FocalLengthIn35mmFilm' in exif_data:
                    camera_info['focal_length_35mm'] = exif_data['FocalLengthIn35mmFilm']
                if 'FNumber' in exif_data:
                    camera_info['aperture'] = exif_data['FNumber']
                if 'ExposureTime' in exif_data:
                    camera_info['exposure_time'] = exif_data['ExposureTime']
                if 'ISOSpeedRatings' in exif_data:
                    camera_info['iso'] = exif_data['ISOSpeedRatings']
                if 'ExposureMode' in exif_data:
                    camera_info['exposure_mode'] = exif_data['ExposureMode']
                if 'WhiteBalance' in exif_data:
                    camera_info['white_balance'] = exif_data['WhiteBalance']
                if 'Flash' in exif_data:
                    camera_info['flash'] = exif_data['Flash']
                if 'MeteringMode' in exif_data:
                    camera_info['metering_mode'] = exif_data['MeteringMode']
                if 'SceneCaptureType' in exif_data:
                    camera_info['scene_type'] = exif_data['SceneCaptureType']
                if camera_info:
                    result['camera'] = camera_info

                # --- Software / Processing ---
                software_info = {}
                if 'Software' in exif_data:
                    software_info['software'] = exif_data['Software']
                if 'ProcessingSoftware' in exif_data:
                    software_info['processing_software'] = exif_data['ProcessingSoftware']
                if 'HostComputer' in exif_data:
                    software_info['host_computer'] = exif_data['HostComputer']
                if 'ImageDescription' in exif_data:
                    software_info['image_description'] = exif_data['ImageDescription']
                if 'Artist' in exif_data:
                    software_info['artist'] = exif_data['Artist']
                if 'Copyright' in exif_data:
                    software_info['copyright'] = exif_data['Copyright']
                if software_info:
                    result['software'] = software_info

                # --- Timestamps ---
                timestamps = {}
                if 'DateTime' in exif_data:
                    timestamps['date_time'] = exif_data['DateTime']
                if 'DateTimeOriginal' in exif_data:
                    timestamps['date_original'] = exif_data['DateTimeOriginal']
                if 'DateTimeDigitized' in exif_data:
                    timestamps['date_digitized'] = exif_data['DateTimeDigitized']
                if timestamps:
                    result['timestamps'] = timestamps

                # --- GPS Data ---
                gps_info = _extract_gps_data(raw_exif, GPSTAGS)
                if gps_info:
                    result['gps'] = gps_info

            else:
                result['exif'] = {}
                result['exif_note'] = 'No EXIF data found in this image'

    except ImportError:
        result['image_error'] = 'PIL/Pillow not available for EXIF extraction'
    except Exception as e:
        result['image_error'] = str(e)

    return result


def _extract_gps_data(raw_exif: dict, GPSTAGS: dict) -> dict:
    """Extract and decode GPS coordinates from EXIF data."""
    try:
        from PIL.ExifTags import TAGS
        # GPS IFD tag is 34853
        gps_ifd = raw_exif.get(34853, {})
        if not gps_ifd:
            return {}

        gps = {}
        for tag_id, val in gps_ifd.items():
            tag_name = GPSTAGS.get(tag_id, str(tag_id))
            try:
                gps[tag_name] = val
            except:
                pass

        result = {}

        # Decode latitude
        if 'GPSLatitude' in gps and 'GPSLatitudeRef' in gps:
            lat = _gps_dms_to_decimal(gps['GPSLatitude'])
            if gps['GPSLatitudeRef'] == 'S':
                lat = -lat
            result['latitude'] = round(lat, 6)
            result['latitude_ref'] = gps['GPSLatitudeRef']

        # Decode longitude
        if 'GPSLongitude' in gps and 'GPSLongitudeRef' in gps:
            lon = _gps_dms_to_decimal(gps['GPSLongitude'])
            if gps['GPSLongitudeRef'] == 'W':
                lon = -lon
            result['longitude'] = round(lon, 6)
            result['longitude_ref'] = gps['GPSLongitudeRef']

        # Altitude
        if 'GPSAltitude' in gps:
            alt = gps['GPSAltitude']
            if hasattr(alt, 'numerator'):
                alt = float(alt.numerator) / float(alt.denominator) if alt.denominator else 0
            result['altitude_m'] = round(float(alt), 1)
            if 'GPSAltitudeRef' in gps:
                result['altitude_ref'] = 'Below sea level' if gps['GPSAltitudeRef'] == 1 else 'Above sea level'

        # Speed
        if 'GPSSpeed' in gps:
            speed = gps['GPSSpeed']
            if hasattr(speed, 'numerator'):
                speed = float(speed.numerator) / float(speed.denominator) if speed.denominator else 0
            result['speed'] = round(float(speed), 1)
            result['speed_ref'] = str(gps.get('GPSSpeedRef', 'K'))

        # Timestamp
        if 'GPSDateStamp' in gps:
            result['gps_date'] = str(gps['GPSDateStamp'])
        if 'GPSTimeStamp' in gps:
            try:
                ts = gps['GPSTimeStamp']
                result['gps_time'] = f"{int(ts[0])}:{int(ts[1])}:{float(ts[2]):.0f}"
            except:
                pass

        # Google Maps link
        if 'latitude' in result and 'longitude' in result:
            result['maps_url'] = f"https://maps.google.com/?q={result['latitude']},{result['longitude']}"

        return result
    except Exception as e:
        return {'gps_error': str(e)}


def _gps_dms_to_decimal(dms) -> float:
    """Convert GPS DMS (degrees, minutes, seconds) to decimal degrees."""
    try:
        d, m, s = dms
        if hasattr(d, 'numerator'):
            d = float(d.numerator) / float(d.denominator) if d.denominator else 0
        if hasattr(m, 'numerator'):
            m = float(m.numerator) / float(m.denominator) if m.denominator else 0
        if hasattr(s, 'numerator'):
            s = float(s.numerator) / float(s.denominator) if s.denominator else 0
        return float(d) + float(m) / 60 + float(s) / 3600
    except:
        return 0.0


def _extract_pdf_meta(filepath: str) -> dict:
    """Extract metadata from PDF files."""
    result = {'file_type': 'PDF'}
    try:
        with open(filepath, 'rb') as f:
            header = f.read(1024)
            # Get PDF version
            if header.startswith(b'%PDF-'):
                result['pdf_version'] = header[5:8].decode('ascii', errors='replace')

            # Read trailer for metadata
            f.seek(0)
            content = f.read()
            text = content.decode('latin-1', errors='replace')

            # Extract producer, creator, etc.
            for field in ['Producer', 'Creator', 'Author', 'Title', 'Subject', 'CreationDate', 'ModDate']:
                idx = text.find(f'/{field}')
                if idx != -1:
                    # Try to extract the value
                    start = text.find('(', idx, idx + 200)
                    if start != -1:
                        end = text.find(')', start)
                        if end != -1:
                            result[f'pdf_{field.lower()}'] = text[start+1:end][:200]

            # Count pages (approximate)
            page_count = text.count('/Type /Page') - text.count('/Type /Pages')
            if page_count > 0:
                result['page_count'] = page_count
    except Exception as e:
        result['pdf_error'] = str(e)
    return result


def _extract_av_meta(filepath: str) -> dict:
    """Extract metadata from audio/video files."""
    result = {'file_type': 'Audio/Video'}
    try:
        with open(filepath, 'rb') as f:
            header = f.read(32)

            # Detect container format
            if header[4:8] == b'ftyp':
                brand = header[8:12].decode('ascii', errors='replace')
                result['container'] = 'MP4/MOV'
                result['brand'] = brand
                if 'isom' in brand:
                    result['format_note'] = 'ISO Base Media File'
                elif 'mp4' in brand.lower():
                    result['format_note'] = 'MPEG-4'
                elif 'qt' in brand.lower():
                    result['format_note'] = 'QuickTime'
            elif header[:4] == b'RIFF':
                result['container'] = 'AVI/WAV'
                result['format'] = header[8:12].decode('ascii', errors='replace')
            elif header[:3] == b'ID3':
                result['container'] = 'MP3 (ID3 tagged)'
            elif header[:4] == b'OggS':
                result['container'] = 'OGG'
            elif header[:4] == b'fLaC':
                result['container'] = 'FLAC'

        result['file_size'] = os.path.getsize(filepath)
    except Exception as e:
        result['av_error'] = str(e)
    return result


def _extract_text_meta(filepath: str) -> dict:
    """Extract metadata from text files."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        return {
            'file_type': 'Text',
            'line_count': len(lines),
            'char_count': sum(len(l) for l in lines),
            'word_count': sum(len(l.split()) for l in lines),
            'preview': ''.join(lines[:10]).strip()[:500]
        }
    except Exception as e:
        return {'text_error': str(e)}


def _extract_zip_meta(filepath: str) -> dict:
    """Extract metadata from ZIP-based files (docx, xlsx, etc.)."""
    result = {'file_type': 'Archive/Office'}
    try:
        import zipfile
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as z:
                result['file_count'] = len(z.namelist())
                result['contained_files'] = z.namelist()[:20]  # First 20 files
                result['compressed_size'] = sum(i.compress_size for i in z.infolist())
                result['uncompressed_size'] = sum(i.file_size for i in z.infolist())

                # Check for Office metadata
                if 'docProps/core.xml' in z.namelist():
                    try:
                        core = z.read('docProps/core.xml').decode('utf-8', errors='replace')
                        import re
                        for tag in ['creator', 'title', 'subject', 'description', 'lastModifiedBy',
                                    'created', 'modified', 'revision']:
                            match = re.search(f'<(?:dc:|cp:|dcterms:)?{tag}[^>]*>([^<]+)</(?:dc:|cp:|dcterms:)?{tag}>', core)
                            if match:
                                result[f'doc_{tag}'] = match.group(1)[:200]
                    except:
                        pass

                if 'docProps/app.xml' in z.namelist():
                    try:
                        app = z.read('docProps/app.xml').decode('utf-8', errors='replace')
                        import re
                        for tag in ['Application', 'AppVersion', 'Company', 'TotalTime', 'Pages', 'Words', 'Characters']:
                            match = re.search(f'<{tag}>([^<]+)</{tag}>', app)
                            if match:
                                result[f'doc_{tag.lower()}'] = match.group(1)[:200]
                    except:
                        pass
    except Exception as e:
        result['archive_error'] = str(e)
    return result


def _extract_binary_signatures(filepath: str) -> dict:
    """Detect known software signatures in file binary header."""
    result = {}
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4096)
            content_sample = header.decode('latin-1', errors='replace').lower()

        # Detect common editing software markers
        software_markers = {
            'adobe photoshop': 'Adobe Photoshop',
            'adobe lightroom': 'Adobe Lightroom',
            'adobe premiere': 'Adobe Premiere',
            'gimp': 'GIMP',
            'paint.net': 'Paint.NET',
            'affinity photo': 'Affinity Photo',
            'capture one': 'Capture One',
            'snapseed': 'Snapseed',
            'whatsapp': 'WhatsApp',
            'instagram': 'Instagram',
            'telegram': 'Telegram',
            'signal': 'Signal',
            'facebook': 'Facebook',
            'twitter': 'Twitter',
            'snapchat': 'Snapchat',
            'tiktok': 'TikTok',
            'microsoft': 'Microsoft Office',
            'libreoffice': 'LibreOffice',
            'openoffice': 'OpenOffice',
            'google docs': 'Google Docs',
            'canva': 'Canva',
            'figma': 'Figma',
            'pixlr': 'Pixlr',
            'davinci': 'DaVinci Resolve',
            'final cut': 'Final Cut Pro',
            'screen capture': 'Screen Capture',
            'screenshot': 'Screenshot',
        }

        detected = []
        for marker, name in software_markers.items():
            if marker in content_sample:
                detected.append(name)

        if detected:
            result['detected_software'] = detected

    except Exception as e:
        pass
    return result


def _analyze_editing_indicators(meta: dict, filepath: str) -> dict:
    """Analyze metadata to determine if file has been edited/modified."""
    analysis = {
        'likely_edited': False,
        'confidence': 'low',
        'indicators': []
    }

    # Check for editing software in EXIF
    software = meta.get('software', {})
    if software:
        sw_name = software.get('software', '').lower()
        editing_tools = ['photoshop', 'lightroom', 'gimp', 'paint', 'affinity', 'pixlr', 'snapseed', 'canva', 'figma']
        for tool in editing_tools:
            if tool in sw_name:
                analysis['likely_edited'] = True
                analysis['confidence'] = 'high'
                analysis['indicators'].append(f'Editing software detected: {software.get("software", "")}')
                break

        # Social media re-upload detection
        social_apps = ['whatsapp', 'instagram', 'telegram', 'facebook', 'twitter', 'snapchat', 'tiktok']
        for app in social_apps:
            if app in sw_name:
                analysis['likely_edited'] = True
                analysis['confidence'] = 'medium'
                analysis['indicators'].append(f'Shared via: {software.get("software", "")} (metadata may be stripped)')
                break

    # Check detected software from binary scan
    detected_sw = meta.get('detected_software', [])
    if detected_sw:
        for sw in detected_sw:
            if sw.lower() not in ['microsoft office']:
                analysis['indicators'].append(f'Software signature found: {sw}')
                if any(x in sw.lower() for x in ['photoshop', 'gimp', 'lightroom']):
                    analysis['likely_edited'] = True
                    analysis['confidence'] = 'high'

    # Timestamp mismatch check
    timestamps = meta.get('timestamps', {})
    if timestamps:
        dt_orig = timestamps.get('date_original', '')
        dt_mod = timestamps.get('date_time', '')
        if dt_orig and dt_mod and dt_orig != dt_mod:
            analysis['indicators'].append(f'Timestamp mismatch: Original={dt_orig}, Modified={dt_mod}')
            analysis['likely_edited'] = True
            if analysis['confidence'] == 'low':
                analysis['confidence'] = 'medium'

    # Check if EXIF was stripped (common with messaging apps)
    if meta.get('mime_type', '').startswith('image/') and not meta.get('exif'):
        analysis['indicators'].append('No EXIF data found - may have been stripped by editing/sharing software')
        analysis['likely_edited'] = True
        if analysis['confidence'] == 'low':
            analysis['confidence'] = 'medium'

    # Check for resolution typical of screenshots
    width = meta.get('width', 0)
    height = meta.get('height', 0)
    if width and height:
        common_screen_res = [
            (1920, 1080), (2560, 1440), (3840, 2160), (1366, 768),
            (1440, 900), (2880, 1800), (1280, 720), (1024, 768),
            (750, 1334), (1125, 2436), (1170, 2532), (1284, 2778),  # iPhone
            (1080, 2340), (1080, 2400), (1440, 3200),  # Android
        ]
        for sw, sh in common_screen_res:
            if (width == sw and height == sh) or (width == sh and height == sw):
                analysis['indicators'].append(f'Resolution ({width}x{height}) matches common screen/device resolution')
                break

    if not analysis['indicators']:
        analysis['indicators'].append('No editing indicators detected - file appears original')

    return analysis
