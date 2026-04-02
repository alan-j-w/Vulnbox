import json
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from core.models import Channel, Message

@login_required
def community_hub(request):
    channels = Channel.objects.all()
    return render(request, "community_hub.html", {"channels": channels})

@login_required
def channel_detail(request, channel_id):
    channel = get_object_or_404(Channel, id=channel_id)
    return render(request, "channel_detail.html", {"channel": channel})

@ratelimit(key='user', rate='20/m', block=False)
@login_required
@csrf_exempt
def send_message(request, channel_id):
    if getattr(request, 'limited', False):
        return JsonResponse({"success": False, "error": "Rate limit exceeded."}, status=429)
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8"))
            content = data.get("content", "").strip()
        except Exception:
            content = request.POST.get("content", "").strip()
        if not content:
            return JsonResponse({"success": False, "error": "Empty message."})
        channel = get_object_or_404(Channel, id=channel_id)
        message = Message.objects.create(channel=channel, author=request.user, content=content)
        profile_picture = request.user.profile_picture.url if hasattr(request.user, "profile_picture") and request.user.profile_picture else "/static/images/default.png"
        return JsonResponse({
            "success": True,
            "author": message.author.username,
            "content": message.content,
            "timestamp": message.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "profile_picture": profile_picture,
        })
    return JsonResponse({"success": False, "error": "Invalid request method."})

@login_required
def fetch_messages(request, channel_id):
    channel = get_object_or_404(Channel, id=channel_id)
    messages = channel.messages.order_by("created_at")
    data = []
    for msg in messages:
        profile_picture = msg.author.profile_picture.url if hasattr(msg.author, "profile_picture") and msg.author.profile_picture else "/static/images/default.png"
        data.append({
            "author": msg.author.username,
            "content": msg.content,
            "timestamp": msg.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "profile_picture": profile_picture,
            "is_own_message": msg.author == request.user,
        })
    return JsonResponse({"messages": data})
