@extends('layouts.admin')

@section('title')
    Proxy Settings
@endsection

@section('content-header')
    <h1>Proxy Settings<small>Configure how reverse proxies are managed.</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Proxy Settings</li>
    </ol>
@endsection

@section('content')
    @include('admin.settings.nav', ['activeTab' => 'proxy'])
    <div class="row">
        <div class="col-xs-12">
            <form action="{{ route('admin.settings.proxy') }}" method="POST">
                <div class="box">
                    <div class="box-header with-border">
                        <h3 class="box-title">Webserver Configuration</h3>
                    </div>
                    <div class="box-body">
                        <div class="row">
                            <div class="form-group col-md-4">
                                <label class="control-label">Webserver Type</label>
                                <div>
                                    <select class="form-control" name="proxy:webserver">
                                        <option value="nginx" @if($webserver === 'nginx') selected @endif>Nginx</option>
                                        <option value="apache" @if($webserver === 'apache') selected @endif>Apache</option>
                                    </select>
                                    <p class="text-muted"><small>Select which webserver is used on your nodes for reverse
                                            proxy configurations.</small></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="box-footer">
                        {!! csrf_field() !!}
                        <button type="submit" name="_method" value="PATCH"
                            class="btn btn-sm btn-primary pull-right">Save</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
@endsection